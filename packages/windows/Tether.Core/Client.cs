using System.Security.Cryptography;
using System.Text.Json;

namespace Tether;

public interface ITetherClient
{
    string AppId {get;}
    Task<IReadOnlyList<PeerRecord>> RecordsAsync(CancellationToken token=default);
    Task<PeerRecord> PairAsync(TetherRoute route,string code,CancellationToken token=default);
    Task<PeerRecord> RecoverAsync(PeerRecord peer,CancellationToken token=default);
    Task<HostStatus> StatusAsync(PeerRecord peer,CancellationToken token=default);
    Task LeaveAsync(PeerRecord peer,CancellationToken token=default);
    Task<PeerRecord> ChangeRouteAsync(PeerRecord peer,TetherRoute route,CancellationToken token=default);
    Task<LocalForgetResult> ForgetLocallyAsync(PeerRecord peer,CancellationToken token=default);
    Task DiscardPendingPairingAsync(PeerRecord peer,CancellationToken token=default);
    Task<TetherMediaStream> OpenMediaAsync(PeerRecord peer,string service,CancellationToken token=default);
    Task<TetherServiceStream> OpenServiceAsync(PeerRecord peer,string service,ServiceKind kind,CancellationToken token=default);
    /// <summary>Pairs by comparing a six-digit code shown on both devices. <paramref name="onCode"/> must complete only once the code is on screen;
    /// <paramref name="decision"/> returns this device owner's answer, or null while undecided; <paramref name="onStoring"/> fires when the
    /// acknowledgement is about to make the pairing irreversible, after which cancelling leaves it pending rather than declined.</summary>
    Task<NearbyOutcome> PairNearbyAsync(TetherRoute route,string deviceName,string deviceKind,Func<string,Task> onCode,Func<Task>? onHostApproved,Func<bool?> decision,CancellationToken token=default,Func<Task>? onStoring=null,string? inviteToken=null)=>throw new TetherException(TetherError.NearbyRefused);
}
public sealed class TetherClient : ITetherClient,IDisposable
{
    public string AppId {get;}
    private readonly TetherProtectedStore store;private Identity? identity;private readonly object identityGate=new();private readonly Dictionary<Guid,Action> owned=new();private readonly bool allowLoopback;private readonly SemaphoreSlim pairing=new(1);private int streams,closed;
    public TetherClient(string appId,TetherProtectedStore? store=null,bool allowInsecureLoopbackForTesting=false)
    {Scope.Validate(appId);AppId=appId;this.store=store??new(appId);if(this.store.AppId!=appId)throw new TetherException(TetherError.InvalidScope);allowLoopback=allowInsecureLoopbackForTesting;}
    private Identity CurrentIdentity {get{lock(identityGate){EnsureOpen();return identity??=store.Identity();}}}
    private void Track(Guid lease,Action abort){lock(identityGate){EnsureOpen();owned.Add(lease,abort);}}
    private void Released(Guid lease){lock(identityGate)owned.Remove(lease);Interlocked.Decrement(ref streams);}
    public Task<IReadOnlyList<PeerRecord>> RecordsAsync(CancellationToken token=default){token.ThrowIfCancellationRequested();EnsureOpen();return Task.FromResult(store.Records());}
    public async Task<PeerRecord> PairAsync(TetherRoute route,string code,CancellationToken token=default)
    {
        EnsureOpen();if(!await pairing.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try {
            await using var session=await Session.Connect(route,CurrentIdentity,AppId,null,allowLoopback,token);
            if(store.Find(Convert.ToBase64String(session.Peer))!=null)throw new TetherException(TetherError.PairingExists);
            NativeResponse begun;
            try{begun=Native.Call(new(){{"command","code.begin"},{"app",AppId},{"code",code},{"binding",session.Binding},{"clientKey",CurrentIdentity.Public},{"hostKey",session.Peer}});}
            catch(TetherException e)when(e.Code==TetherError.Protocol){throw new TetherException(TetherError.Authentication);}
            using(begun)return await Drive(session,route,begun,null,null,null,token) is NearbyOutcome.Paired paired?paired.Record:throw new TetherException(TetherError.Protocol);
        }finally{pairing.Release();}
    }
    /// <summary><paramref name="inviteToken"/> is the one-time token this device issued to a computer that invited it; it is
    /// repeated to the host so the host's owner can see which request answered that invite.</summary>
    public async Task<NearbyOutcome> PairNearbyAsync(TetherRoute route,string deviceName,string deviceKind,Func<string,Task> onCode,Func<Task>? onHostApproved,Func<bool?> decision,CancellationToken token=default,Func<Task>? onStoring=null,string? inviteToken=null)
    {
        EnsureOpen();if(route.Mode!="direct")throw new TetherException(TetherError.NearbyRefused);if(!await pairing.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try {
            await using var session=await Session.Connect(route,CurrentIdentity,AppId,null,allowLoopback,token);
            if(store.Find(Convert.ToBase64String(session.Peer))!=null)throw new TetherException(TetherError.PairingExists);
            // The shared flow applies the approval rules: an answer counts only after the code has been up for a second and the
            // decision has read undecided since it appeared; a decline is final and beats a racing ready.
            var request=new Dictionary<string,object?>{{"command","nearby.begin"},{"app",AppId},{"binding",session.Binding},{"clientKey",CurrentIdentity.Public},{"hostKey",session.Peer},{"name",deviceName},{"kind",deviceKind}};
            if(inviteToken is not null)request["inviteToken"]=inviteToken;
            using var begun=Native.Call(request);
            return await Drive(session,route,begun,onCode,onHostApproved,decision,token,onStoring);
        }finally{pairing.Release();}
    }
    private static List<JsonElement> Actions(NativeResponse response)=>response.RootElement.GetProperty("actions").EnumerateArray().Select(a=>a.Clone()).ToList();
    /// <summary>Performs a shared Rust pairing flow's actions until it ends; trust is saved only when it says so.</summary>
    private async Task<NearbyOutcome> Drive(Session session,TetherRoute route,NativeResponse begun,Func<string,Task>? onCode,Func<Task>? onHostApproved,Func<bool?>? decision,CancellationToken token,Func<Task>? onStoring=null)
    {
        // Cancelling before the acknowledgement is a decline.
        bool? Decide()=>token.IsCancellationRequested?false:decision?.Invoke();
        using var flow=new NativeHandle(Native.Handle(begun.RootElement));var clock=System.Diagnostics.Stopwatch.StartNew();
        var hostKey=Convert.ToBase64String(session.Peer);PeerRecord? pending=null,confirmed=null;var actions=Actions(begun);
        List<JsonElement> Step(string command,bool decided){var request=new Dictionary<string,object?>{{"command",command},{"handle",flow.Value},{"now",clock.ElapsedMilliseconds}};if(decided)request["decision"]=Decide();using var r=Native.Call(request);return Actions(r);}
        while(true)
        {
            List<JsonElement>? next=null;
            foreach(var action in actions)
            {
                token.ThrowIfCancellationRequested();
                switch(action.GetProperty("do").GetString())
                {
                    case "send":await session.SendRecord(action.GetProperty("message"),token);break;
                    case "receive":
                        using(var message=await session.Record(token))
                        using(var r=Native.Call(new(){{"command","flow.receive"},{"handle",flow.Value},{"message",message.RootElement},{"decision",Decide()},{"now",clock.ElapsedMilliseconds}}))next=Actions(r);
                        break;
                    case "wait":await Task.Delay(action.TryGetProperty("ms",out var ms)?ms.GetInt32():600,token);next=Step("flow.tick",true);break;
                    case "show_code":
                        var code=action.GetProperty("code").GetString();if(code is not{Length:6}||!code.All(char.IsAsciiDigit))throw new TetherException(TetherError.Protocol);
                        // Only once the code is on screen does its read time start.
                        if(onCode!=null)await onCode(code);next=Step("flow.shown",true);break;
                    case "host_approved":if(onHostApproved!=null)await onHostApproved();break;
                    case "store_pending":
                        // Pending trust is durable before the host receives its acknowledgement.
                        pending=new PeerRecord(AppId,hostKey,Convert.ToBase64String(CurrentIdentity.Public),route,false,Guid.NewGuid());store.Begin(pending);
                        if(onStoring!=null)await onStoring();next=Step("flow.stored",true);break;
                    case "discard_pending":
                        // A decline that arrived before the ack still wins; the pending record goes again.
                        if(pending!=null)store.Remove(pending,false);pending=null;break;
                    case "confirm":confirmed=store.Confirm(pending??throw new TetherException(TetherError.PairingPending));break;
                    case "outcome":return action.GetProperty("outcome").GetString() switch{"paired"=>new NearbyOutcome.Paired(confirmed??throw new TetherException(TetherError.PairingPending)),"declined"=>new NearbyOutcome.Declined(),"expired"=>new NearbyOutcome.Expired(),_=>throw new TetherException(TetherError.Protocol)};
                    case "failed":throw new TetherException(TetherCopy.Error(action.TryGetProperty("code",out var c)?c.GetString():null));
                    default:throw new TetherException(TetherError.Protocol);
                }
            }
            actions=next??throw new TetherException(TetherError.Protocol);
        }
    }
    internal static string Label(string raw)=>TetherCopy.Label(raw,"Device");
    private async Task<Session> Connect(PeerRecord peer,CancellationToken token)
    {EnsureOpen();peer.Validate(AppId);if(store.Find(peer.HostKey)!=peer||Convert.ToBase64String(CurrentIdentity.Public)!=peer.ClientKey)throw new TetherException(TetherError.IdentityMismatch);return await Session.Connect(peer.Route,CurrentIdentity,AppId,Scope.Key(peer.HostKey),allowLoopback,token);}
    public async Task<PeerRecord> RecoverAsync(PeerRecord peer,CancellationToken token=default)
    {await using var session=await Connect(peer,token);await session.SendControl("pair.status",token);using var done=await session.Control("pair.done",token);return store.Confirm(peer);}
    public Task DiscardPendingPairingAsync(PeerRecord peer,CancellationToken token=default)
    {token.ThrowIfCancellationRequested();EnsureOpen();store.Remove(peer,false);return Task.CompletedTask;}
    public async Task<HostStatus> StatusAsync(PeerRecord peer,CancellationToken token=default)
    {
        if(!peer.Confirmed)throw new TetherException(TetherError.PairingPending);await using var session=await Connect(peer,token);await session.SendControl("host.status",token);using var result=await session.Control("host.status",token);
        return ParseStatus(result.RootElement);
    }
    private static HostStatus ParseStatus(JsonElement root)
    {
        var services=root.GetProperty("services");if(services.ValueKind!=JsonValueKind.Array||services.GetArrayLength()>32)throw new TetherException(TetherError.Protocol);var list=new List<HostService>();
        foreach(var service in services.EnumerateArray()){var id=service.GetProperty("id").GetString()??throw new TetherException(TetherError.Protocol);Scope.Validate(id);var kind=service.GetProperty("kind").GetString()switch{"tcp"=>ServiceKind.Tcp,"udp"=>ServiceKind.Udp,_=>throw new TetherException(TetherError.Protocol)};if(list.Any(s=>s.Id==id))throw new TetherException(TetherError.Protocol);list.Add(new(id,kind));}
        return new HostStatus(list);
    }
    public async Task<PeerRecord> ChangeRouteAsync(PeerRecord peer,TetherRoute route,CancellationToken token=default)
    {
        EnsureOpen();peer.Validate(AppId);if(!peer.Confirmed)throw new TetherException(TetherError.PairingPending);
        if(store.Find(peer.HostKey)!=peer||Convert.ToBase64String(CurrentIdentity.Public)!=peer.ClientKey)throw new TetherException(TetherError.IdentityMismatch);
        await using var session=await Session.Connect(route,CurrentIdentity,AppId,Scope.Key(peer.HostKey),allowLoopback,token);
        await session.SendControl("host.status",token);using var status=await session.Control("host.status",token);
        _=ParseStatus(status.RootElement);
        var changed=peer with{Route=route,PairingId=Guid.NewGuid()};store.ReplaceConfirmed(peer,changed);return changed;
    }
    public async Task LeaveAsync(PeerRecord peer,CancellationToken token=default)
    {if(!peer.Confirmed)throw new TetherException(TetherError.PairingPending);await using var session=await Connect(peer,token);await session.SendControl("peer.leave",token);try{using var ack=await session.Control("peer.left",token);}catch(TetherException e)when(e.Code==TetherError.Revoked){}store.Remove(peer,true);}
    public Task<LocalForgetResult> ForgetLocallyAsync(PeerRecord peer,CancellationToken token=default)
    {token.ThrowIfCancellationRequested();EnsureOpen();store.Remove(peer,true);return Task.FromResult(LocalForgetResult.LocalTrustRemovedHostUnchanged);}
    public async Task<TetherServiceStream> OpenServiceAsync(PeerRecord peer,string service,ServiceKind kind,CancellationToken token=default)
    {
        Scope.Validate(service);if(!peer.Confirmed)throw new TetherException(TetherError.PairingPending);if(Interlocked.Increment(ref streams)>8){Interlocked.Decrement(ref streams);throw new TetherException(TetherError.Busy);}Session? session=null;var releasedOnFailure=false;
        try{session=await Connect(peer,token);await session.SendControl("service.open",token,new(){{"service",service}});using var ready=await session.Control("service.ready",token);if(ready.RootElement.GetProperty("kind").GetString()!=(kind==ServiceKind.Tcp?"tcp":"udp"))throw new TetherException(TetherError.ServiceRefused);var lease=Guid.NewGuid();var stream=new TetherServiceStream(kind,session,()=>Released(lease));try{Track(lease,stream.Abort);}catch{await stream.DisposeAsync();releasedOnFailure=true;throw;}return stream;}
        catch{if(session!=null)await session.DisposeAsync();if(!releasedOnFailure)Interlocked.Decrement(ref streams);throw;}
    }
    public async Task<TetherMediaStream> OpenMediaAsync(PeerRecord peer,string service,CancellationToken token=default)
    {
        Scope.Validate(service);if(peer.Route.Mode!="direct")throw new TetherException(TetherError.MediaUnavailable);if(!peer.Confirmed)throw new TetherException(TetherError.PairingPending);
        if(Interlocked.Increment(ref streams)>8){Interlocked.Decrement(ref streams);throw new TetherException(TetherError.Busy);}Session? session=null;var releasedOnFailure=false;
        try{session=await Connect(peer,token);var lease=Guid.NewGuid();var stream=await TetherMediaStream.Open(session,peer.Route,service,()=>Released(lease),token);try{Track(lease,stream.Abort);}catch{await stream.DisposeAsync();releasedOnFailure=true;throw;}return stream;}
        catch{if(session!=null)await session.DisposeAsync();if(!releasedOnFailure)Interlocked.Decrement(ref streams);throw;}
    }
    private void EnsureOpen(){if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);}
    public void Dispose(){Action[] resources;Identity? key;lock(identityGate){if(Interlocked.Exchange(ref closed,1)!=0)return;resources=owned.Values.ToArray();owned.Clear();key=identity;identity=null;}foreach(var abort in resources)abort();key?.Dispose();}
}
public sealed class TetherServiceStream : IAsyncDisposable
{
    public ServiceKind Kind {get;}private readonly Session session;private readonly Action released;private int closed,sentFin,receivedFin;internal event Action? Closed;
    internal void Abort()=>DisposeAsync().AsTask().GetAwaiter().GetResult();
    internal TetherServiceStream(ServiceKind kind,Session session,Action released){Kind=kind;this.session=session;this.released=released;}
    public async Task SendAsync(ReadOnlyMemory<byte> bytes,CancellationToken token=default)
    {token.ThrowIfCancellationRequested();if(closed!=0||sentFin!=0)throw new TetherException(TetherError.Closed);if(bytes.Length>16384)throw new TetherException(TetherError.Protocol);if(Kind==ServiceKind.Tcp&&bytes.IsEmpty)return;var copy=bytes.ToArray();try{await session.Send(copy,token);}catch(TetherException e)when(e.Code==TetherError.Busy){throw;}catch(OperationCanceledException)when(token.IsCancellationRequested){if(session.IsClosed)await DisposeAsync();throw;}catch{await DisposeAsync();throw;}finally{CryptographicOperations.ZeroMemory(copy);}}
    public async Task<byte[]?> ReceiveAsync(CancellationToken token=default)
    {token.ThrowIfCancellationRequested();if(closed!=0)throw new TetherException(TetherError.Closed);if(receivedFin!=0)return null;try{var bytes=await session.Receive(token);if(bytes.Length>16384)throw new TetherException(TetherError.Protocol);if(Kind==ServiceKind.Tcp&&bytes.Length==0){receivedFin=1;if(sentFin!=0)await DisposeAsync();return null;}return bytes;}catch(TetherException e)when(e.Code==TetherError.Busy){throw;}catch(OperationCanceledException)when(token.IsCancellationRequested){if(session.IsClosed)await DisposeAsync();throw;}catch{await DisposeAsync();throw;}}
    public async Task FinishSendingAsync(CancellationToken token=default)
    {token.ThrowIfCancellationRequested();if(Kind!=ServiceKind.Tcp||closed!=0||Interlocked.Exchange(ref sentFin,1)!=0)throw new TetherException(TetherError.Closed);try{await session.Send(Array.Empty<byte>(),token);if(receivedFin!=0)await DisposeAsync();}catch(TetherException e)when(e.Code==TetherError.Busy){Interlocked.Exchange(ref sentFin,0);throw;}catch{await DisposeAsync();throw;}}
    public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref closed,1)==0){try{await session.DisposeAsync();}finally{released();Closed?.Invoke();GC.SuppressFinalize(this);}}}
}
