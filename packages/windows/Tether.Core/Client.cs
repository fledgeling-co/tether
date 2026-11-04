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
            var hostKey=Convert.ToBase64String(session.Peer);if(store.Find(hostKey)!=null)throw new TetherException(TetherError.PairingExists);
            using var start=Native.Call(new(){{"command","pairing.start"},{"role","client"},{"code",code},{"app",AppId},{"binding",session.Binding},{"clientKey",CurrentIdentity.Public},{"hostKey",session.Peer}});
            using var exchange=new NativeHandle(Native.Handle(start.RootElement));
            await session.SendControl("pair.start",token,new(){{"element",Native.Data(start.RootElement,"data",33)}});
            using var reply=await session.Control("pair.reply",token);var element=Native.Data(reply.RootElement,"element",33);var hostProof=Native.Data(reply.RootElement,"proof",32);
            using var finished=Native.Call(new(){{"command","pairing.finish"},{"handle",exchange.Take()},{"data",element}});
            using var proof=new NativeHandle(Native.Handle(finished.RootElement));var outbound=Native.Data(finished.RootElement,"data",32);
            using(var verified=Native.Call(new(){{"command","pairing.verify"},{"handle",proof.Take()},{"data",hostProof}})){}
            await session.SendControl("pair.confirm",token,new(){{"proof",outbound}});using(var ready=await session.Control("pair.ready",token)){}
            var record=new PeerRecord(AppId,hostKey,Convert.ToBase64String(CurrentIdentity.Public),route,false,Guid.NewGuid());
            store.Begin(record); // Pending trust is durable before the host receives its acknowledgement.
            await session.SendControl("pair.ack",token);using(var done=await session.Control("pair.done",token)){}
            return store.Confirm(record);
        }finally{pairing.Release();}
    }
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
