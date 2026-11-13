using System.Collections.Concurrent;
using System.ComponentModel;

namespace Tether;

public sealed record TetherManagedHost(PeerRecord Record,ConnectionState State,IReadOnlyList<HostService> Services,DateTimeOffset? LastChecked=null,string? Notice=null)
{public string Id=>Record.Id;internal long Generation{get;init;}}
public sealed record TetherReconnectPolicy
{
    public IReadOnlyList<TimeSpan> RetryDelays {get;}
    public TimeSpan ProbeInterval {get;}
    public TetherReconnectPolicy(IReadOnlyList<TimeSpan>? retryDelays=null,TimeSpan? probeInterval=null)
    {RetryDelays=(retryDelays??new[]{TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(2),TimeSpan.FromSeconds(4)}).ToArray();ProbeInterval=probeInterval??TimeSpan.FromSeconds(15);if(RetryDelays.Count>5||RetryDelays.Any(x=>x<TimeSpan.FromMilliseconds(10)||x>TimeSpan.FromSeconds(30))||ProbeInterval<TimeSpan.FromMilliseconds(10)||ProbeInterval>TimeSpan.FromMinutes(5))throw new ArgumentOutOfRangeException(nameof(retryDelays));}
}
/// <summary>Saved trust is offline until a fresh pinned status reply arrives. Notifications use the creating UI context.</summary>
public sealed class TetherConnectionStore : INotifyPropertyChanged,IAsyncDisposable
{
    private readonly ITetherClient client;private readonly TetherReconnectPolicy policy;private readonly SynchronizationContext? context;
    private readonly object state=new();private readonly Dictionary<string,TetherManagedHost> hosts=new(StringComparer.Ordinal);
    private readonly Dictionary<string,CancellationTokenSource> monitors=new(StringComparer.Ordinal);
    private readonly Dictionary<Guid,(string Host,long Generation,IAsyncDisposable Stream)> streams=new();
    private readonly Dictionary<string,SemaphoreSlim> operations=new(StringComparer.Ordinal);private readonly SemaphoreSlim trust=new(1);
    private long generation;private bool closed;private string? selected;
    public event PropertyChangedEventHandler? PropertyChanged;
    /// <summary>The application this store's client is scoped to.</summary>
    public string AppId=>client.AppId;
    public IReadOnlyList<TetherManagedHost> Hosts {get{lock(state)return hosts.Values.OrderBy(h=>h.Id,StringComparer.Ordinal).ToArray();}}
    public string? SelectedHostId {get{lock(state)return selected;}set{lock(state){EnsureOpen();if(value!=null&&!hosts.ContainsKey(value))throw new TetherException(TetherError.IdentityMismatch);selected=value;}Changed(nameof(SelectedHostId));}}
    public TetherConnectionStore(ITetherClient client,TetherReconnectPolicy? reconnectPolicy=null){this.client=client;policy=reconnectPolicy??new();context=SynchronizationContext.Current;}
    private void Changed(string name=nameof(Hosts)){if(context!=null&&context!=SynchronizationContext.Current)context.Post(_=>PropertyChanged?.Invoke(this,new(name)),null);else PropertyChanged?.Invoke(this,new(name));}
    private void EnsureOpen(){if(closed)throw new TetherException(TetherError.Closed);}
    private TetherManagedHost Find(string id){lock(state){EnsureOpen();return hosts.TryGetValue(id,out var h)?h:throw new TetherException(TetherError.IdentityMismatch);}}
    private SemaphoreSlim Enter(string id,CancellationToken token)
    {lock(state){EnsureOpen();if(!hosts.ContainsKey(id))throw new TetherException(TetherError.IdentityMismatch);if(!operations.TryGetValue(id,out var gate))operations[id]=gate=new(1);if(!gate.Wait(0,token))throw new TetherException(TetherError.Busy);return gate;}}
    private void Exit(string id,SemaphoreSlim gate){lock(state){gate.Release();if(!hosts.ContainsKey(id))operations.Remove(id);}}
    // Metadata changes are atomic. Network and stream disposal always occur outside this lock.
    private List<IAsyncDisposable> RetireLocked(string id,bool cancelMonitor=true)
    {
        if(hosts.TryGetValue(id,out var host))hosts[id]=host with{Generation=++generation,State=host.Record.Confirmed?ConnectionState.Offline:ConnectionState.Pending,Services=Array.Empty<HostService>()};
        if(cancelMonitor&&monitors.Remove(id,out var source)){source.Cancel();source.Dispose();}
        var retired=new List<IAsyncDisposable>();foreach(var item in streams.Where(p=>p.Value.Host==id).ToArray()){streams.Remove(item.Key);retired.Add(item.Value.Stream);}return retired;
    }
    private static async Task Close(IEnumerable<IAsyncDisposable> values){foreach(var value in values)await value.DisposeAsync().ConfigureAwait(false);}
    public async Task LoadAsync(CancellationToken token=default){await trust.WaitAsync(token);try{await Reload(token);}finally{trust.Release();}}
    private async Task Reload(CancellationToken token)
    {
        lock(state)EnsureOpen();var records=await client.RecordsAsync(token);foreach(var peer in records)peer.Validate(client.AppId);if(records.Count>256||records.Select(p=>p.Id).Distinct(StringComparer.Ordinal).Count()!=records.Count)throw new TetherException(TetherError.Protocol);
        var retired=new List<IAsyncDisposable>();lock(state){EnsureOpen();var ids=records.Select(p=>p.Id).ToHashSet(StringComparer.Ordinal);
            foreach(var id in hosts.Keys.Where(id=>!ids.Contains(id)).ToArray()){retired.AddRange(RetireLocked(id));hosts.Remove(id);if(operations.TryGetValue(id,out var gate)&&gate.CurrentCount==1)operations.Remove(id);}
            foreach(var peer in records){if(hosts.TryGetValue(peer.Id,out var old)&&old.Record==peer)continue;retired.AddRange(RetireLocked(peer.Id));hosts[peer.Id]=new(peer,peer.Confirmed?ConnectionState.Offline:ConnectionState.Pending,Array.Empty<HostService>()){Generation=++generation};}
            if(selected==null||!ids.Contains(selected))selected=hosts.Values.OrderBy(h=>h.Id,StringComparer.Ordinal).FirstOrDefault()?.Id;
        }await Close(retired);Changed();Changed(nameof(SelectedHostId));
    }
    public async Task<TetherManagedHost> PairAsync(TetherRoute route,string code,CancellationToken token=default)
    {
        await trust.WaitAsync(token);PeerRecord peer;try{lock(state)EnsureOpen();try{peer=await client.PairAsync(route,code,token);}finally{await Reload(CancellationToken.None);}}finally{trust.Release();}
        SelectedHostId=peer.Id;await ConnectAsync(peer.Id,token);return Find(peer.Id);
    }
    /// <summary>Pairs with a nearby computer by comparing a code, then selects and connects it.</summary>
    public async Task<NearbyOutcome> PairNearbyAsync(TetherRoute route,string deviceName,string deviceKind,Func<string,Task> onCode,Func<Task>? onHostApproved,Func<bool?> decision,CancellationToken token=default,Func<Task>? onStoring=null)
    {
        await trust.WaitAsync(token);NearbyOutcome outcome;try{lock(state)EnsureOpen();try{outcome=await client.PairNearbyAsync(route,deviceName,deviceKind,onCode,onHostApproved,decision,token,onStoring);}finally{await Reload(CancellationToken.None);}}finally{trust.Release();}
        if(outcome is NearbyOutcome.Paired paired){SelectedHostId=paired.Record.Id;await ConnectAsync(paired.Record.Id,token);}return outcome;
    }
    public Task ReconnectAsync(string id,CancellationToken token=default)=>ConnectAsync(id,token);
    public async Task ConnectAsync(string id,CancellationToken token=default){var gate=Enter(id,token);try{await ConnectCore(id,token);}finally{Exit(id,gate);}}
    private async Task ConnectCore(string id,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();CancellationTokenSource source;CancellationToken sourceToken;long epoch;List<IAsyncDisposable> retired;bool confirmed;
        lock(state){EnsureOpen();if(!hosts.TryGetValue(id,out var host))throw new TetherException(TetherError.IdentityMismatch);retired=RetireLocked(id);host=hosts[id];epoch=host.Generation;confirmed=host.Record.Confirmed;hosts[id]=host with{State=confirmed?ConnectionState.Connecting:ConnectionState.Pending,Notice=null};source=new();sourceToken=source.Token;if(confirmed)monitors[id]=source;}
        await Close(retired);Changed();if(!confirmed){source.Dispose();return;}
        using var cancel=token.Register(()=>{try{source.Cancel();}catch(ObjectDisposedException){}});var result=await Probe(id,epoch,sourceToken);
        if(token.IsCancellationRequested){await DisconnectAsync(id);token.ThrowIfCancellationRequested();}
        if(result.Continue)_=Monitor(id,result.Epoch,sourceToken);
    }
    public async Task DisconnectAsync(string id){List<IAsyncDisposable> retired;lock(state){EnsureOpen();if(!hosts.ContainsKey(id))throw new TetherException(TetherError.IdentityMismatch);retired=RetireLocked(id);}await Close(retired);Changed();}
    private bool Current(string id,long epoch,out TetherManagedHost host){lock(state){if(!closed&&hosts.TryGetValue(id,out host!)&&host.Generation==epoch)return true;host=null!;return false;}}
    private async Task<(bool Continue,long Epoch)> Probe(string id,long epoch,CancellationToken token)
    {
        try{if(!Current(id,epoch,out var host))return(false,epoch);var status=await client.StatusAsync(host.Record,token);lock(state){if(!Current(id,epoch,out host))return(false,epoch);hosts[id]=host with{State=ConnectionState.Connected,Services=status.Services.ToArray(),LastChecked=DateTimeOffset.UtcNow,Notice=null};}Changed();return(true,epoch);}
        catch(OperationCanceledException)when(token.IsCancellationRequested){return(false,epoch);}
        catch(Exception error){var typed=error as TetherException;var terminal=typed?.Code is TetherError.IdentityMismatch or TetherError.Revoked;List<IAsyncDisposable> retired;long next;
            lock(state){if(!Current(id,epoch,out var host))return(false,epoch);retired=RetireLocked(id,terminal);next=hosts[id].Generation;hosts[id]=hosts[id] with{State=typed?.Code switch{TetherError.Revoked=>ConnectionState.Revoked,TetherError.IdentityMismatch=>ConnectionState.IdentityMismatch,TetherError.Capacity=>ConnectionState.Capacity,_=>ConnectionState.Offline},Notice=typed?.Code is TetherError.Revoked or TetherError.IdentityMismatch or TetherError.Capacity?typed.Message:"The host did not answer. Saved trust was kept."};}
            await Close(retired);Changed();return(!terminal,next);
        }
    }
    private async Task Monitor(string id,long epoch,CancellationToken token)
    {
        try{var failures=0;while(!token.IsCancellationRequested&&Current(id,epoch,out var host)){
            var delay=host.State==ConnectionState.Connected?policy.ProbeInterval:failures<policy.RetryDelays.Count?policy.RetryDelays[failures++]:Timeout.InfiniteTimeSpan;
            if(delay==Timeout.InfiniteTimeSpan){List<IAsyncDisposable> retired;lock(state){if(!Current(id,epoch,out _))return;retired=RetireLocked(id);}await Close(retired);Changed();return;}
            if(host.State is not(ConnectionState.Connected or ConnectionState.Capacity)){lock(state){if(!Current(id,epoch,out host))return;hosts[id]=host with{State=ConnectionState.Reconnecting};}Changed();}
            await Task.Delay(delay,token);var result=await Probe(id,epoch,token);if(!result.Continue)return;epoch=result.Epoch;if(Current(id,epoch,out host)&&host.State==ConnectionState.Connected)failures=0;
        }}catch(OperationCanceledException)when(token.IsCancellationRequested){}catch{List<IAsyncDisposable> retired;lock(state){if(!Current(id,epoch,out _))return;retired=RetireLocked(id);}await Close(retired);Changed();}
    }
    private (TetherManagedHost Host,CancellationToken Token) ForOpen(string id)
    {lock(state){var host=Find(id);if(host.State!=ConnectionState.Connected||!monitors.TryGetValue(id,out var source))throw new TetherException(TetherError.Unavailable);return(host,source.Token);}}
    private bool Track(TetherManagedHost host,Guid lease,IAsyncDisposable stream)
    {lock(state){if(!Current(host.Id,host.Generation,out var current)||current.State!=ConnectionState.Connected)return false;streams[lease]=(host.Id,host.Generation,stream);return true;}}
    private void Released(Guid lease){lock(state)streams.Remove(lease);}
    public async Task<TetherServiceStream> OpenServiceAsync(string id,string service,ServiceKind kind,CancellationToken token=default)
    {var (host,lifetime)=ForOpen(id);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,lifetime);var stream=await client.OpenServiceAsync(host.Record,service,kind,linked.Token);var lease=Guid.NewGuid();stream.Closed+=()=>Released(lease);if(linked.IsCancellationRequested||!Track(host,lease,stream)){await stream.DisposeAsync();throw new TetherException(TetherError.Closed);}return stream;}
    public async Task<TetherMediaStream> OpenMediaAsync(string id,string service,CancellationToken token=default)
    {var (host,lifetime)=ForOpen(id);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,lifetime);var stream=await client.OpenMediaAsync(host.Record,service,linked.Token);var lease=Guid.NewGuid();stream.Closed+=()=>Released(lease);if(linked.IsCancellationRequested||!Track(host,lease,stream)){await stream.DisposeAsync();throw new TetherException(TetherError.Closed);}return stream;}
    private async Task Mutate(string id,Func<PeerRecord,CancellationToken,Task> action,CancellationToken token)
    {var gate=Enter(id,token);try{await trust.WaitAsync(token);try{var peer=Find(id).Record;await DisconnectAsync(id);try{await action(peer,token);}finally{await Reload(CancellationToken.None);}}finally{trust.Release();}}finally{Exit(id,gate);}}
    public async Task ChangeRouteAsync(string id,TetherRoute route,CancellationToken token=default)
    {var gate=Enter(id,token);try{await trust.WaitAsync(token);try{var peer=Find(id).Record;try{_=await client.ChangeRouteAsync(peer,route,token);}finally{await Reload(CancellationToken.None);}}finally{trust.Release();}token.ThrowIfCancellationRequested();await ConnectCore(id,token);}finally{Exit(id,gate);}}
    public Task LeaveAsync(string id,CancellationToken token=default)=>Mutate(id,client.LeaveAsync,token);
    public Task ForgetLocallyAsync(string id,CancellationToken token=default)=>Mutate(id,async(peer,t)=>{_=await client.ForgetLocallyAsync(peer,t);},token);
    public Task DiscardPendingPairingAsync(string id,CancellationToken token=default)=>Mutate(id,client.DiscardPendingPairingAsync,token);
    public Task RecoverAsync(string id,CancellationToken token=default)=>Mutate(id,async(peer,t)=>{_=await client.RecoverAsync(peer,t);},token);
    public async ValueTask DisposeAsync(){List<IAsyncDisposable> retired=new();lock(state){if(closed)return;closed=true;foreach(var id in hosts.Keys.ToArray())retired.AddRange(RetireLocked(id));}await Close(retired).ConfigureAwait(false);}
}
