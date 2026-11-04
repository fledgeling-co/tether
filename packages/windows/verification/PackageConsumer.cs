using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Tether;

var root=Path.Combine(Path.GetTempPath(),"tether-package-consumer-"+Guid.NewGuid().ToString("N"));
try {
    using var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
    await using var host=new TetherHostController("test.package",Path.Combine(root,"host","host.dpapi"));
    using var client=new TetherClient("test.package",new("test.package",Path.Combine(root,"client")));
    await host.InitializeAsync(new[]{new HostServiceProfile("audio",ServiceKind.Udp,"127.0.0.1",(ushort)((IPEndPoint)udp.Client.LocalEndPoint!).Port)});
    var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=(ushort)((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
    await host.StartAsync(HostRoute.Direct("127.0.0.1",port));var window=await host.OpenPairingWindowAsync();var peer=await client.PairAsync(TetherRoute.Direct("127.0.0.1",port),window.Code);await host.RefreshPairingStatusAsync();
    if(!peer.Confirmed||(await client.StatusAsync(peer)).Services.Single().Id!="audio"||host.Pairing!=null)throw new InvalidOperationException("Packaged pairing/status contract failed");
    await using(var stream=await client.OpenServiceAsync(peer,"audio",ServiceKind.Udp)){using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));var packet=new byte[]{3,2,1};await stream.SendAsync(packet,timeout.Token);var received=await udp.ReceiveAsync(timeout.Token);await udp.SendAsync(received.Buffer,received.RemoteEndPoint,timeout.Token);if(!(await stream.ReceiveAsync(timeout.Token))!.SequenceEqual(packet))throw new InvalidOperationException("Packaged UDP roundtrip failed");}
    object mediaMeasurement;
    await using(var media=await client.OpenMediaAsync(peer,"audio")){
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10));var encoded=await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"encoded-audio.ogg"),timeout.Token);var times=new List<double>();
        for(int i=0;i<64;i++){var clock=System.Diagnostics.Stopwatch.StartNew();await media.SendAsync(encoded,timeout.Token);var received=await udp.ReceiveAsync(timeout.Token);await udp.SendAsync(received.Buffer,received.RemoteEndPoint,timeout.Token);if(!(await media.ReceiveAsync(timeout.Token)).SequenceEqual(encoded))throw new InvalidOperationException("Packaged media mismatch");times.Add(clock.Elapsed.TotalMilliseconds);}
        times.Sort();mediaMeasurement=new{packets=times.Count,bytesPerPacket=encoded.Length,maxDatagram=media.MaxDatagram,rttP50Milliseconds=times[31],rttP95Milliseconds=times[60],path="Packaged .NET10 SDK / shared Rust QUIC / loopback UDP echo",paced=false,decoded=false};
    }
    await client.LeaveAsync(peer);await host.RefreshClientsAsync();if(host.Clients.Count!=0||(await client.RecordsAsync()).Count!=0)throw new InvalidOperationException("Packaged leave readback failed");
    Console.WriteLine(JsonSerializer.Serialize(new{schema="tether.windows-package-consumer/1",runtime=Environment.Version.ToString(),paired=true,status=true,udp=true,left=true,helperPresent=File.Exists(Path.Combine(AppContext.BaseDirectory,"tether.exe")),media=mediaMeasurement,source="Local NuGet package reference; no project reference."}));
}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
