using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Tether.Core.Tests;

/// <summary>Native Windows fixtures: real C# SDK, shared Rust DLL, managed owner pipe and network listeners.</summary>
public sealed class NetworkTests
{
    private static readonly byte[] Request=Encoding.ASCII.GetBytes("GET /health HTTP/1.1\r\nHost: fixture\r\n\r\n");
    [Fact]public async Task Direct_pair_status_tcp_api_udp_route_cas_revoke_leave_and_durable_owner_readback()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(45));var token=timeout.Token;
        using var client=fixture.Client("one");var peer=await fixture.Pair(client,fixture.Route,token);
        Assert.True(peer.Confirmed);Assert.Equal(new[]{"api","audio"},(await client.StatusAsync(peer,token)).Services.Select(s=>s.Id).OrderBy(s=>s).ToArray());
        await Api(client,peer,token);await using(var udp=await client.OpenServiceAsync(peer,"audio",ServiceKind.Udp,token)){var packet=new byte[]{0,1,2,255};await udp.SendAsync(packet,token);Assert.Equal(packet,await udp.ReceiveAsync(token));await udp.SendAsync(Array.Empty<byte>(),token);Assert.Empty((await udp.ReceiveAsync(token))!);}
        var changed=await client.ChangeRouteAsync(peer,TetherRoute.Direct("localhost",fixture.Port),token);Assert.NotEqual(peer.PairingId,changed.PairingId);Assert.Equal(peer.HostKey,changed.HostKey);await Api(client,changed,token);
        await using(var impostor=await Fixture.Create()){var error=await Assert.ThrowsAsync<TetherException>(()=>client.ChangeRouteAsync(changed,impostor.Route,token));Assert.Equal(TetherError.IdentityMismatch,error.Code);Assert.Equal(changed,Assert.Single(await client.RecordsAsync(token)));}
        await using(var active=await client.OpenServiceAsync(changed,"audio",ServiceKind.Udp,token)){await fixture.Host.RefreshClientsAsync(token);var authorized=Assert.Single(fixture.Host.Clients);Assert.True(authorized.ActiveSessions>0);await fixture.Host.RevokeAsync(authorized.Id,token);Assert.Empty(fixture.Host.Clients);var denied=await Assert.ThrowsAsync<TetherException>(()=>client.StatusAsync(changed,token));Assert.Equal(TetherError.Revoked,denied.Code);Assert.Single(await client.RecordsAsync(token));}
        using var second=fixture.Client("two");var leaving=await fixture.Pair(second,fixture.Route,token);await second.LeaveAsync(leaving,token);Assert.Empty(await second.RecordsAsync(token));await fixture.Host.RefreshClientsAsync(token);Assert.Empty(fixture.Host.Clients);
        await fixture.Host.StopAsync();await fixture.Host.InspectAsync(token);await fixture.Host.RefreshClientsAsync(token);Assert.Empty(fixture.Host.Clients);Assert.Equal(HostRunState.Stopped,fixture.Host.State);
    }
    [Fact]public async Task Real_two_host_connections_keep_second_stream_when_first_disconnects_or_route_changes()
    {
        await using var a=await Fixture.Create();await using var b=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(35));var token=timeout.Token;
        using var client=a.Client("multi");var first=await a.Pair(client,a.Route,token);var second=await b.Pair(client,b.Route,token);
        await using var store=new TetherConnectionStore(client,new(Array.Empty<TimeSpan>(),TimeSpan.FromMinutes(5)));await store.LoadAsync(token);Assert.All(store.Hosts,h=>Assert.Equal(ConnectionState.Offline,h.State));
        await store.ConnectAsync(first.Id,token);await store.ConnectAsync(second.Id,token);await using var stream=await store.OpenServiceAsync(second.Id,"audio",ServiceKind.Udp,token);
        await store.ChangeRouteAsync(first.Id,TetherRoute.Direct("localhost",a.Port),token);await store.DisconnectAsync(first.Id);Assert.Equal(ConnectionState.Connected,store.Hosts.Single(h=>h.Id==second.Id).State);
        var packet=Encoding.UTF8.GetBytes("host-b-only");await stream.SendAsync(packet,token);Assert.Equal(packet,await stream.ReceiveAsync(token));await store.DisconnectAsync(second.Id);Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>stream.SendAsync(packet,token))).Code);
    }
    [Fact]public async Task Loopback_websocket_relay_carries_real_pairing_status_and_tcp_udp_but_never_auto_selects_media()
    {
        await using var fixture=await Fixture.Create(false);using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(35));var token=timeout.Token;var relayPort=FreePort();
        using var relay=new Process{StartInfo=Fixture.Info("tether-relay.exe",new[]{"127.0.0.1:"+relayPort,"--allow-host",fixture.Host.HostId!})};Assert.True(relay.Start());var stdout=relay.StandardOutput.BaseStream.CopyToAsync(Stream.Null);var stderr=relay.StandardError.BaseStream.CopyToAsync(Stream.Null);
        try{await WaitListener(relayPort,token);await fixture.Host.StartAsync(HostRoute.Cloud("ws://127.0.0.1:"+relayPort+"/v1/relay"),token);Assert.Equal(HostRunState.RelayConnected,fixture.Host.State);using var client=fixture.Client("relay");var peer=await fixture.Pair(client,TetherRoute.Cloud("ws://127.0.0.1:"+relayPort+"/v1/relay",fixture.Host.HostId!),token);await Api(client,peer,token);
            await using(var udp=await client.OpenServiceAsync(peer,"audio",ServiceKind.Udp,token)){var packet=new byte[]{9,8,7};await udp.SendAsync(packet,token);Assert.Equal(packet,await udp.ReceiveAsync(token));}
            Assert.Equal(TetherError.MediaUnavailable,(await Assert.ThrowsAsync<TetherException>(()=>client.OpenMediaAsync(peer,"audio",token))).Code);await client.LeaveAsync(peer,token);Assert.Empty(await client.RecordsAsync(token));await fixture.Host.OpenPairingWindowAsync(token);relay.Kill(true);await relay.WaitForExitAsync(token);while(fixture.Host.State!=HostRunState.RelayDisconnected){token.ThrowIfCancellationRequested();await Task.Delay(10,token);}Assert.Null(fixture.Host.Pairing);Assert.Equal(TetherError.Unavailable,(await Assert.ThrowsAsync<TetherException>(()=>fixture.Host.OpenPairingWindowAsync(token))).Code);
        }finally{await fixture.Host.StopAsync();try{if(!relay.HasExited)relay.Kill(true);}catch{}await relay.WaitForExitAsync();await Task.WhenAll(stdout,stderr);}
    }
    [Fact]public async Task Native_media_wrapper_uses_authenticated_lease_negotiated_payload_heartbeat_stats_and_cancellation()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));var token=timeout.Token;using var client=fixture.Client("media");var peer=await fixture.Pair(client,fixture.Route,token);
        await using var media=await client.OpenMediaAsync(peer,"audio",token);Assert.InRange(media.MaxDatagram,1,1200);Assert.True(media.MaxDatagram<=1152);
        foreach(var name in new[]{"audio.ogg","video.h264"}){var encoded=await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"fixtures",name),token);for(var offset=0;offset<encoded.Length;offset+=media.MaxDatagram){var packet=encoded.AsMemory(offset,Math.Min(media.MaxDatagram,encoded.Length-offset)).ToArray();await media.SendAsync(packet,token);Assert.Equal(packet,await media.ReceiveAsync(token));}}
        // Outlive the five-second host lease: only real encrypted heartbeats can keep this route alive.
        await Task.Delay(TimeSpan.FromSeconds(6),token);await media.SendAsync(new byte[]{42},token);Assert.Equal(new byte[]{42},await media.ReceiveAsync(token));var stats=media.Statistics();Assert.True(stats.BytesSent>0&&stats.BytesReceived>0&&stats.PacketsSent>0);
        Assert.Equal(TetherError.Protocol,(await Assert.ThrowsAsync<TetherException>(()=>media.SendAsync(new byte[media.MaxDatagram+1],token))).Code);
        var waiting=media.ReceiveAsync(token);Assert.Equal(TetherError.Busy,(await Assert.ThrowsAsync<TetherException>(()=>media.ReceiveAsync(token))).Code);await media.SendAsync(new byte[]{7},token);Assert.Equal(new byte[]{7},await waiting);
        using var cancel=new CancellationTokenSource(TimeSpan.FromMilliseconds(30));await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>media.ReceiveAsync(cancel.Token).WaitAsync(TimeSpan.FromSeconds(2)));Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>media.SendAsync(new byte[]{1},token))).Code);
    }
    [Fact]public async Task Busy_or_precancelled_calls_do_not_dispose_another_operation_and_client_disposal_closes_owned_streams()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));var token=timeout.Token;using var client=fixture.Client("ownership");var peer=await fixture.Pair(client,fixture.Route,token);await using var stream=await client.OpenServiceAsync(peer,"audio",ServiceKind.Udp,token);
        var receiving=stream.ReceiveAsync(token);Assert.Equal(TetherError.Busy,(await Assert.ThrowsAsync<TetherException>(()=>stream.ReceiveAsync(token))).Code);using var cancel=new CancellationTokenSource();cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>stream.SendAsync(new byte[]{5},cancel.Token));await stream.SendAsync(new byte[]{6},token);Assert.Equal(new byte[]{6},await receiving);client.Dispose();Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>stream.SendAsync(new byte[]{7},token))).Code);
    }
    [Fact]public async Task Actual_owner_revocation_retires_controller_media_and_streams_including_inflight_receive()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));var token=timeout.Token;using var client=fixture.Client("terminal");var peer=await fixture.Pair(client,fixture.Route,token);await using var store=new TetherConnectionStore(client,new(Array.Empty<TimeSpan>(),TimeSpan.FromMilliseconds(80)));await store.LoadAsync(token);await store.ConnectAsync(peer.Id,token);await using var stream=await store.OpenServiceAsync(peer.Id,"audio",ServiceKind.Udp,token);await using var media=await store.OpenMediaAsync(peer.Id,"audio",token);await fixture.Host.RefreshClientsAsync(token);await fixture.Host.RevokeAsync(Assert.Single(fixture.Host.Clients).Id,token);
        while(store.Hosts.Single().State!=ConnectionState.Revoked){token.ThrowIfCancellationRequested();await Task.Delay(10,token);}Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>stream.SendAsync(new byte[]{1},token))).Code);await Assert.ThrowsAsync<TetherException>(()=>media.SendAsync(new byte[]{1},token));Assert.Single(await client.RecordsAsync(token));await client.LeaveAsync(peer,token);Assert.Empty(await client.RecordsAsync(token));
    }
    [Fact]public async Task Unexpected_helper_exit_keeps_offline_owner_readback_and_revoke_available_and_dispose_prevents_restart()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));var token=timeout.Token;using var client=fixture.Client("helper-exit");var peer=await fixture.Pair(client,fixture.Route,token);await fixture.Host.RefreshClientsAsync(token);var id=Assert.Single(fixture.Host.Clients).Id;
        using(var process=Process.GetProcessById(fixture.Host.OwnedProcessId!.Value)){process.Kill(true);await process.WaitForExitAsync(token);}while(fixture.Host.State!=HostRunState.Failed){token.ThrowIfCancellationRequested();await Task.Delay(10,token);}Assert.Null(fixture.Host.OwnedProcessId);await fixture.Host.RefreshClientsAsync(token);Assert.Single(fixture.Host.Clients);await fixture.Host.RevokeAsync(id,token);Assert.Empty(fixture.Host.Clients);await fixture.Host.StartAsync(HostRoute.Direct("127.0.0.1",fixture.Port),token);await fixture.Host.DisposeAsync();Assert.Null(fixture.Host.OwnedProcessId);Assert.Equal(TetherError.Closed,(await Assert.ThrowsAsync<TetherException>(()=>fixture.Host.StartAsync(HostRoute.Direct("127.0.0.1",fixture.Port),token))).Code);
    }
    [Fact]public async Task Media_cancellation_returns_without_waiting_for_cleanup_and_concurrent_disposers_share_completion()
    {
        await using var fixture=await Fixture.Create();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));var token=timeout.Token;var protectedStore=fixture.ClientStore("close-task");using var client=new TetherClient("test.native",protectedStore);var peer=await fixture.Pair(client,fixture.Route,token);using var identity=protectedStore.Identity();var delay=new DelayedClose();
        var session=await Session.Connect(peer.Route,identity,"test.native",Scope.Key(peer.HostKey),true,token,carrier=>delay.Wrap(carrier));var released=0;var media=await TetherMediaStream.Open(session,peer.Route,"audio",()=>Interlocked.Increment(ref released),token);using var cancel=new CancellationTokenSource();var receive=media.ReceiveAsync(cancel.Token);
        try{await Task.Delay(20,token);await Task.Run(cancel.Cancel).WaitAsync(TimeSpan.FromSeconds(1));await delay.Entered.Task.WaitAsync(TimeSpan.FromSeconds(2));var first=media.DisposeAsync().AsTask();var second=media.DisposeAsync().AsTask();Assert.Same(first,second);Assert.False(first.IsCompleted);Assert.Equal(0,released);delay.Release.TrySetResult(true);await Task.WhenAll(first,second).WaitAsync(TimeSpan.FromSeconds(2));await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>receive);Assert.Equal(1,released);}
        finally{delay.Release.TrySetResult(true);await media.DisposeAsync();try{await receive;}catch{}}
    }
    private sealed class DelayedClose
    {
        internal readonly TaskCompletionSource<bool> Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ICarrier Wrap(ICarrier inner)=>new Adapter(inner,this);
        private sealed class Adapter(ICarrier inner,DelayedClose delay) : ICarrier
        {public Task SendAsync(byte[] bytes,CancellationToken token)=>inner.SendAsync(bytes,token);public Task<byte[]> ReceiveAsync(CancellationToken token)=>inner.ReceiveAsync(token);public async ValueTask DisposeAsync(){delay.Entered.TrySetResult(true);await delay.Release.Task.ConfigureAwait(false);await inner.DisposeAsync().ConfigureAwait(false);}}
    }
    private static async Task Api(TetherClient client,PeerRecord peer,CancellationToken token)
    {await using var stream=await client.OpenServiceAsync(peer,"api",ServiceKind.Tcp,token);await stream.SendAsync(Request,token);using var reply=new MemoryStream();while(reply.Length<Fixture.Response.Length){var bytes=await stream.ReceiveAsync(token);Assert.NotNull(bytes);reply.Write(bytes!);}Assert.Equal(Fixture.Response,reply.ToArray());}
    internal static ushort FreePort(){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=(ushort)((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();return port;}
    private static async Task WaitListener(ushort port,CancellationToken token){while(true){token.ThrowIfCancellationRequested();using var tcp=new TcpClient();try{await tcp.ConnectAsync(IPAddress.Loopback,port,token);return;}catch(SocketException){await Task.Delay(20,token);}}}
    private sealed class Fixture : IAsyncDisposable
    {
        internal static readonly byte[] Response=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
        private readonly string root=Path.Combine(Path.GetTempPath(),"tether-native-sdk-"+Guid.NewGuid().ToString("N"));private readonly CancellationTokenSource lifetime=new();private readonly TcpListener tcp=new(IPAddress.Loopback,0);private readonly UdpClient udp=new(new IPEndPoint(IPAddress.Loopback,0));private Task? tcpLoop,udpLoop;
        internal TetherHostController Host {get;private set;}=null!;internal ushort Port {get;private set;}internal TetherRoute Route=>TetherRoute.Direct("127.0.0.1",Port);
        internal static ProcessStartInfo Info(string executable,IEnumerable<string> arguments){var info=new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,executable)){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};info.Environment.Clear();foreach(var name in new[]{"SystemRoot","WINDIR","TEMP","TMP","USERPROFILE","LOCALAPPDATA","APPDATA","PROGRAMDATA"})if(Environment.GetEnvironmentVariable(name)is{} value)info.Environment[name]=value;foreach(var argument in arguments)info.ArgumentList.Add(argument);return info;}
        internal static async Task<Fixture> Create(bool start=true){var f=new Fixture();try{f.tcp.Start();f.tcpLoop=f.TcpLoop();f.udpLoop=f.UdpLoop();f.Host=new("test.native",Path.Combine(f.root,"host","host.dpapi"),allowInsecureLoopbackForTesting:true);await f.Host.InitializeAsync(new[]{new HostServiceProfile("api",ServiceKind.Tcp,"127.0.0.1",(ushort)((IPEndPoint)f.tcp.LocalEndpoint).Port),new HostServiceProfile("audio",ServiceKind.Udp,"127.0.0.1",(ushort)((IPEndPoint)f.udp.Client.LocalEndPoint!).Port)});f.Port=FreePort();if(start)await f.Host.StartAsync(HostRoute.Direct("127.0.0.1",f.Port));return f;}catch{await f.DisposeAsync();throw;}}
        internal TetherProtectedStore ClientStore(string name)=>new("test.native",Path.Combine(root,"clients",name));
        internal TetherClient Client(string name)=>new("test.native",ClientStore(name),allowInsecureLoopbackForTesting:true);
        internal async Task<PeerRecord> Pair(TetherClient client,TetherRoute route,CancellationToken token){var window=await Host.OpenPairingWindowAsync(token);var peer=await client.PairAsync(route,window.Code,token);await Host.RefreshPairingStatusAsync(token);Assert.Null(Host.Pairing);return peer;}
        private async Task TcpLoop(){try{while(true){var client=await tcp.AcceptTcpClientAsync(lifetime.Token);_=Handle(client);}}catch(OperationCanceledException){}catch(SocketException)when(lifetime.IsCancellationRequested){}}
        private async Task Handle(TcpClient client){using(client)try{var stream=client.GetStream();var data=new byte[4096];using var input=new MemoryStream();while(input.Length<4096){var n=await stream.ReadAsync(data,lifetime.Token);if(n==0)return;input.Write(data,0,n);if(Encoding.ASCII.GetString(input.ToArray()).Contains("\r\n\r\n",StringComparison.Ordinal))break;}if(input.ToArray().SequenceEqual(Request))await stream.WriteAsync(Response,lifetime.Token);}catch(OperationCanceledException){}catch(IOException){}catch(SocketException){}}
        private async Task UdpLoop(){try{while(true){var packet=await udp.ReceiveAsync(lifetime.Token);await udp.SendAsync(packet.Buffer,packet.RemoteEndPoint,lifetime.Token);}}catch(OperationCanceledException){}catch(SocketException)when(lifetime.IsCancellationRequested){}}
        public async ValueTask DisposeAsync(){if(Host!=null)await Host.DisposeAsync();lifetime.Cancel();tcp.Stop();udp.Dispose();try{if(tcpLoop!=null)await tcpLoop;if(udpLoop!=null)await udpLoop;}catch(ObjectDisposedException){}lifetime.Dispose();if(Directory.Exists(root))Directory.Delete(root,true);}
    }
}
