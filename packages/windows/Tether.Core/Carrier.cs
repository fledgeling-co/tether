using System.Buffers.Binary;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text.Json;

namespace Tether;

internal interface ICarrier : IAsyncDisposable { Task SendAsync(byte[] bytes,CancellationToken token);Task<byte[]> ReceiveAsync(CancellationToken token); }
internal static class Deadline
{
    internal static CancellationTokenSource Start(CancellationToken token,int seconds=15){var source=CancellationTokenSource.CreateLinkedTokenSource(token);source.CancelAfter(TimeSpan.FromSeconds(seconds));return source;}
}
internal sealed class TcpCarrier(TcpClient client) : ICarrier
{
    internal static async Task<ICarrier> Connect(TetherRoute route,CancellationToken token)
    {var client=new TcpClient();try{using var deadline=Deadline.Start(token);await client.ConnectAsync(route.Host!,route.Port,deadline.Token);return new TcpCarrier(client);}catch{client.Dispose();throw;}}
    public async Task SendAsync(byte[] bytes,CancellationToken token)
    {if(bytes.Length>65536)throw new TetherException(TetherError.Protocol);using var d=Deadline.Start(token);var frame=new byte[4+bytes.Length];BinaryPrimitives.WriteUInt32BigEndian(frame,(uint)bytes.Length);bytes.CopyTo(frame,4);await client.GetStream().WriteAsync(frame,d.Token);}
    public async Task<byte[]> ReceiveAsync(CancellationToken token)
    {using var d=Deadline.Start(token,60);var header=new byte[4];await client.GetStream().ReadExactlyAsync(header,d.Token);var size=BinaryPrimitives.ReadUInt32BigEndian(header);if(size>65536)throw new TetherException(TetherError.Protocol);var data=new byte[(int)size];await client.GetStream().ReadExactlyAsync(data,d.Token);return data;}
    public ValueTask DisposeAsync(){client.Dispose();return ValueTask.CompletedTask;}
}
internal sealed class WebSocketCarrier(ClientWebSocket socket) : ICarrier
{
    internal static async Task<ICarrier> Connect(TetherRoute route,string appId,CancellationToken token)
    {
        var socket=new ClientWebSocket();socket.Options.UseDefaultCredentials=false;
        try {using var d=Deadline.Start(token);await socket.ConnectAsync(new Uri(route.Url!),d.Token);var carrier=new WebSocketCarrier(socket);
            var metadata=JsonSerializer.SerializeToUtf8Bytes(new{type="client",app_id=appId,host_id=route.HostId});await socket.SendAsync(new ArraySegment<byte>(metadata),WebSocketMessageType.Text,true,d.Token);
            var ready=await carrier.Read(WebSocketMessageType.Text,2048,d.Token);using var json=JsonDocument.Parse(ready);if(json.RootElement.GetProperty("type").GetString()!="ready")throw new TetherException(TetherError.Protocol);return carrier;
        } catch{socket.Abort();socket.Dispose();throw;}
    }
    public async Task SendAsync(byte[] bytes,CancellationToken token)
    {if(bytes.Length>65536)throw new TetherException(TetherError.Protocol);using var d=Deadline.Start(token);await socket.SendAsync(new ArraySegment<byte>(bytes),WebSocketMessageType.Binary,true,d.Token);}
    public async Task<byte[]> ReceiveAsync(CancellationToken token){using var d=Deadline.Start(token,60);return await Read(WebSocketMessageType.Binary,65536,d.Token);}
    private async Task<byte[]> Read(WebSocketMessageType type,int cap,CancellationToken token)
    {using var memory=new MemoryStream();var buffer=new byte[4096];while(true){var result=await socket.ReceiveAsync(new ArraySegment<byte>(buffer),token);if(result.MessageType!=type||memory.Length+result.Count>cap)throw new TetherException(TetherError.Protocol);memory.Write(buffer,0,result.Count);if(result.EndOfMessage)return memory.ToArray();}}
    public ValueTask DisposeAsync(){socket.Abort();socket.Dispose();return ValueTask.CompletedTask;}
}
