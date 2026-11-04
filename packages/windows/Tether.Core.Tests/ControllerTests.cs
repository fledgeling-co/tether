using Xunit;
namespace Tether.Core.Tests;
public sealed class ControllerTests
{
    private static PeerRecord Peer(int n)=>new("test.controller",Convert.ToBase64String(Enumerable.Repeat((byte)n,32).ToArray()),Convert.ToBase64String(new byte[32]),TetherRoute.Direct("127.0.0.1",7445),true,Guid.NewGuid());
    private static TetherReconnectPolicy Quiet()=>new(Array.Empty<TimeSpan>(),TimeSpan.FromMinutes(5));
    [Fact]public async Task Saved_trust_starts_offline_and_never_invents_services()
    {var peer=Peer(1);var fake=new FixtureClient(peer);await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();Assert.Equal(ConnectionState.Offline,Assert.Single(store.Hosts).State);Assert.Empty(store.Hosts[0].Services);Assert.Equal(0,fake.StatusCalls);}
    [Fact]public async Task A_late_status_reply_cannot_undo_disconnect()
    {var peer=Peer(1);var reply=new TaskCompletionSource<HostStatus>(TaskCreationOptions.RunContinuationsAsynchronously);var fake=new FixtureClient(peer){Probe=(_,_)=>reply.Task};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();var connect=store.ConnectAsync(peer.Id);Assert.Equal(ConnectionState.Connecting,store.Hosts[0].State);await store.DisconnectAsync(peer.Id);reply.SetResult(new(new[]{new HostService("api",ServiceKind.Tcp)}));await connect;Assert.Equal(ConnectionState.Offline,store.Hosts[0].State);Assert.Empty(store.Hosts[0].Services);}
    [Fact]public async Task Disconnecting_one_host_leaves_another_connected()
    {var a=Peer(1);var b=Peer(2);var fake=new FixtureClient(a,b);await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(a.Id);await store.ConnectAsync(b.Id);await store.DisconnectAsync(a.Id);Assert.Equal(ConnectionState.Offline,store.Hosts.Single(h=>h.Id==a.Id).State);Assert.Equal(ConnectionState.Connected,store.Hosts.Single(h=>h.Id==b.Id).State);}
    [Fact]public async Task Failed_leave_keeps_the_saved_record()
    {var peer=Peer(1);var fake=new FixtureClient(peer){RefuseLeave=true};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(peer.Id);await Assert.ThrowsAsync<TetherException>(()=>store.LeaveAsync(peer.Id));Assert.Equal(peer,Assert.Single(store.Hosts).Record);Assert.Equal(ConnectionState.Offline,store.Hosts[0].State);Assert.Equal(1,fake.LeaveCalls);}
    [Fact]public async Task Failed_route_probe_keeps_old_route_and_connection()
    {var peer=Peer(1);var fake=new FixtureClient(peer){RefuseRoute=true};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(peer.Id);await Assert.ThrowsAsync<TetherException>(()=>store.ChangeRouteAsync(peer.Id,TetherRoute.Direct("127.0.0.1",7446)));Assert.Equal(peer,Assert.Single(store.Hosts).Record);Assert.Equal(ConnectionState.Connected,store.Hosts[0].State);}
    [Fact]public async Task Route_update_changes_only_its_selected_host_after_success()
    {var a=Peer(1);var b=Peer(2);var fake=new FixtureClient(a,b);await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(a.Id);await store.ConnectAsync(b.Id);var route=TetherRoute.Direct("127.0.0.1",7446);await store.ChangeRouteAsync(a.Id,route);Assert.Equal(route,store.Hosts.Single(h=>h.Id==a.Id).Record.Route);Assert.NotEqual(a.PairingId,store.Hosts.Single(h=>h.Id==a.Id).Record.PairingId);Assert.Equal(ConnectionState.Connected,store.Hosts.Single(h=>h.Id==b.Id).State);}
    [Fact]public async Task Only_explicit_authenticated_revocation_becomes_revoked()
    {var peer=Peer(1);var fake=new FixtureClient(peer){Probe=(_,_)=>throw new TetherException(TetherError.Revoked)};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(peer.Id);Assert.Equal(ConnectionState.Revoked,store.Hosts[0].State);Assert.Single(fake.Peers);}
    [Fact]public async Task Cancel_after_route_commit_still_reloads_authoritative_trust_without_false_identity_mismatch()
    {var peer=Peer(1);using var cancel=new CancellationTokenSource();var fake=new FixtureClient(peer){RouteCommitted=cancel.Cancel};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.ConnectAsync(peer.Id);var route=TetherRoute.Direct("127.0.0.1",7555);await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>store.ChangeRouteAsync(peer.Id,route,cancel.Token));Assert.Equal(route,Assert.Single(store.Hosts).Record.Route);Assert.NotEqual(peer.PairingId,store.Hosts[0].Record.PairingId);Assert.Equal(ConnectionState.Offline,store.Hosts[0].State);await store.ConnectAsync(peer.Id);Assert.Equal(ConnectionState.Connected,store.Hosts[0].State);}
    [Fact]public async Task Cancel_after_leave_commit_does_not_keep_a_deleted_host_selected()
    {var peer=Peer(1);using var cancel=new CancellationTokenSource();var fake=new FixtureClient(peer){LeaveCommitted=cancel.Cancel};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();await store.LeaveAsync(peer.Id,cancel.Token);Assert.Empty(store.Hosts);Assert.Null(store.SelectedHostId);}
    [Fact]public async Task Load_removal_during_delayed_probe_cannot_resurrect_a_host()
    {var peer=Peer(1);var reply=new TaskCompletionSource<HostStatus>(TaskCreationOptions.RunContinuationsAsynchronously);var fake=new FixtureClient(peer){Probe=(_,_)=>reply.Task};await using var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();var connecting=store.ConnectAsync(peer.Id);fake.Peers.Clear();await store.LoadAsync();reply.SetResult(new(Array.Empty<HostService>()));await connecting;Assert.Empty(store.Hosts);}
    [Fact]public async Task Disposed_controller_cannot_late_probe_back_to_connected()
    {var peer=Peer(1);var reply=new TaskCompletionSource<HostStatus>(TaskCreationOptions.RunContinuationsAsynchronously);var fake=new FixtureClient(peer){Probe=(_,_)=>reply.Task};var store=new TetherConnectionStore(fake,Quiet());await store.LoadAsync();var connecting=store.ConnectAsync(peer.Id);await store.DisposeAsync();reply.SetResult(new(Array.Empty<HostService>()));await connecting;Assert.Equal(ConnectionState.Offline,Assert.Single(store.Hosts).State);Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>store.ConnectAsync(peer.Id))).Code);}
    private sealed class FixtureClient(params PeerRecord[] peers) : ITetherClient
    {
        public string AppId=>"test.controller";public List<PeerRecord> Peers=peers.ToList();public int StatusCalls,LeaveCalls;public bool RefuseLeave,RefuseRoute;public Action? RouteCommitted,LeaveCommitted;
        public Func<PeerRecord,CancellationToken,Task<HostStatus>>? Probe;
        public Task<IReadOnlyList<PeerRecord>> RecordsAsync(CancellationToken token=default){token.ThrowIfCancellationRequested();return Task.FromResult<IReadOnlyList<PeerRecord>>(Peers.ToArray());}
        public Task<HostStatus> StatusAsync(PeerRecord peer,CancellationToken token=default){StatusCalls++;return Probe?.Invoke(peer,token)??Task.FromResult(new HostStatus(new[]{new HostService("api",ServiceKind.Tcp)}));}
        public Task LeaveAsync(PeerRecord peer,CancellationToken token=default){LeaveCalls++;if(RefuseLeave)throw new TetherException(TetherError.Unavailable);Peers.Remove(peer);LeaveCommitted?.Invoke();return Task.CompletedTask;}
        public Task<PeerRecord> ChangeRouteAsync(PeerRecord peer,TetherRoute route,CancellationToken token=default){if(RefuseRoute)throw new TetherException(TetherError.Unavailable);var record=peer with{Route=route,PairingId=Guid.NewGuid()};Peers[Peers.IndexOf(peer)]=record;RouteCommitted?.Invoke();return Task.FromResult(record);}
        public Task<LocalForgetResult> ForgetLocallyAsync(PeerRecord peer,CancellationToken token=default){Peers.Remove(peer);return Task.FromResult(LocalForgetResult.LocalTrustRemovedHostUnchanged);}
        public Task<PeerRecord> PairAsync(TetherRoute route,string code,CancellationToken token=default)=>throw new NotSupportedException("Fixture does not pair.");
        public Task<PeerRecord> RecoverAsync(PeerRecord peer,CancellationToken token=default)=>throw new NotSupportedException("Fixture does not recover.");
        public Task DiscardPendingPairingAsync(PeerRecord peer,CancellationToken token=default)=>throw new NotSupportedException("Fixture has no pending record.");
        public Task<TetherMediaStream> OpenMediaAsync(PeerRecord peer,string service,CancellationToken token=default)=>throw new TetherException(TetherError.MediaUnavailable);
        public Task<TetherServiceStream> OpenServiceAsync(PeerRecord peer,string service,ServiceKind kind,CancellationToken token=default)=>throw new NotSupportedException("Fixture never opens a stream.");
    }
}
