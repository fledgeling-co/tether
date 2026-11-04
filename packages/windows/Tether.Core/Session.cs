using System.Security.Cryptography;
using System.Text.Json;

namespace Tether;

internal sealed class Session(ICarrier carrier,NativeHandle cipher,byte[] peer,byte[] binding) : IAsyncDisposable
{
    internal byte[] Peer {get;}=peer;
    internal byte[] Binding {get;}=binding;
    private readonly SemaphoreSlim sending=new(1),receiving=new(1);
    private int closed;internal bool IsClosed=>Volatile.Read(ref closed)!=0;
    internal static async Task<Session> Connect(TetherRoute route,Identity identity,string appId,byte[]? pin,bool allowLoopback,CancellationToken token,Func<ICarrier,ICarrier>? carrierAdapter=null)
    {
        route.Validate(allowLoopback);ICarrier? carrier=null;NativeHandle? noise=null;
        try {
            carrier=route.Mode=="direct"?await TcpCarrier.Connect(route,token):await WebSocketCarrier.Connect(route,appId,token);if(carrierAdapter!=null)carrier=carrierAdapter(carrier);
            using(var response=Native.Call(new(){{"command","noise.new"},{"identity",identity.Handle.Value},{"app",appId},{"role","client"}}))noise=new(Native.Handle(response.RootElement));
            using(var response=Native.Call(new(){{"command","noise.write"},{"handle",noise.Value},{"data",Array.Empty<byte>()}}))await carrier.SendAsync(Native.Data(response.RootElement),token);
            byte[] remote;
            using(var d=Deadline.Start(token))
            using(var response=Native.Call(new(){{"command","noise.read"},{"handle",noise.Value},{"data",await carrier.ReceiveAsync(d.Token)}}))remote=Native.Data(response.RootElement,"remoteStatic",32);
            if(pin!=null&&!CryptographicOperations.FixedTimeEquals(pin,remote))throw new TetherException(TetherError.IdentityMismatch);
            // The host pin is checked before message three reveals the client's static key.
            using(var response=Native.Call(new(){{"command","noise.write"},{"handle",noise.Value},{"data",Array.Empty<byte>()}}))await carrier.SendAsync(Native.Data(response.RootElement),token);
            using var finished=Native.Call(new(){{"command","noise.finish"},{"handle",noise.Take()}});
            var handle=Native.Handle(finished.RootElement);
            try {if(finished.RootElement.GetProperty("finished").ValueKind!=JsonValueKind.True)throw new TetherException(TetherError.Protocol);return new Session(carrier,new(handle),remote,Native.Data(finished.RootElement,"binding",32));}catch{Native.Destroy(handle);throw;}
        } catch(TetherException){if(carrier!=null)await carrier.DisposeAsync();throw;}
          catch(OperationCanceledException){if(carrier!=null)await carrier.DisposeAsync();if(token.IsCancellationRequested)throw;throw new TetherException(TetherError.Unavailable);}
          catch{if(carrier!=null)await carrier.DisposeAsync();throw new TetherException(TetherError.Unavailable);}
        finally{noise?.Dispose();}
    }
    internal async Task Send(byte[] data,CancellationToken token)
    {
        if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);if(!await sending.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try{using var encrypted=Native.Call(new(){{"command","transport.encrypt"},{"handle",cipher.Value},{"data",data}});await carrier.SendAsync(Native.Data(encrypted.RootElement),token);}catch{await DisposeAsync();throw;}finally{sending.Release();}
    }
    internal async Task<byte[]> Receive(CancellationToken token)
    {
        if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);if(!await receiving.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try{var bytes=await carrier.ReceiveAsync(token);using var response=Native.Call(new(){{"command","transport.decrypt"},{"handle",cipher.Value},{"data",bytes}});return Native.Data(response.RootElement);}catch{await DisposeAsync();throw;}finally{receiving.Release();}
    }
    internal async Task SendControl(string type,CancellationToken token,Dictionary<string,object?>? fields=null)
    {var value=fields??new();value["v"]=1;value["type"]=type;var data=JsonSerializer.SerializeToUtf8Bytes(value);try{if(data.Length>4096)throw new TetherException(TetherError.Protocol);await Send(data,token);}finally{CryptographicOperations.ZeroMemory(data);}}
    internal async Task<NativeResponse> Control(string expected,CancellationToken token)
    {
        using var d=Deadline.Start(token);byte[]? bytes=await Receive(d.Token);
        try {if(bytes.Length>4096)throw new TetherException(TetherError.Protocol);var result=new NativeResponse(bytes);bytes=null;try{
            var root=result.RootElement;if(root.GetProperty("v").GetInt32()!=1)throw new TetherException(TetherError.Protocol);var type=root.GetProperty("type").GetString();
            if(type=="error")throw new TetherException(root.TryGetProperty("code",out var code)?code.GetString()switch{"peer_revoked"=>TetherError.Revoked,"service_denied"=>TetherError.ServiceRefused,"service_capacity"=>TetherError.Capacity,"media_unavailable"=>TetherError.MediaUnavailable,_=>TetherError.Protocol}:TetherError.Protocol);
            if(type!=expected)throw new TetherException(TetherError.Protocol);return result;
        }catch{result.Dispose();throw;}}
        catch(TetherException){throw;}catch{throw new TetherException(TetherError.Protocol);}finally{if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
    }
    public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref closed,1)==0){cipher.Dispose();await carrier.DisposeAsync();}}
}
