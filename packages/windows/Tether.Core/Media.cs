using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Tether;

public sealed record TetherMediaStats(double RttMilliseconds,ulong BytesSent,ulong BytesReceived,ulong PacketsSent,ulong PacketsReceived,ulong Dropped);
/// <summary>An explicit private-network QUIC route. DisposeAsync awaits its native receiver and owning Noise session.</summary>
public sealed class TetherMediaStream : IAsyncDisposable
{
    private static readonly SemaphoreSlim WorkerSlots=new(64);
    private readonly Session session;private readonly Action released;private readonly byte[] lease;private readonly int ceiling;
    private readonly CancellationTokenSource lifetime=new();private readonly Task heartbeat;
    private readonly TaskCompletionSource<bool> receiverStopped=new(TaskCreationOptions.RunContinuationsAsynchronously),closeCompleted=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly BlockingCollection<TaskCompletionSource<byte[]>> requests=new(1);private readonly SemaphoreSlim receiving=new(1);
    private long handle;private int closed,maxDatagram;internal event Action? Closed;
    public int MaxDatagram=>Volatile.Read(ref maxDatagram);
    private TetherMediaStream(Session session,ulong handle,byte[] lease,int maximum,Action released)
    {
        this.session=session;this.handle=checked((long)handle);this.lease=lease;maxDatagram=ceiling=maximum;this.released=released;
        if(!WorkerSlots.Wait(0))throw new TetherException(TetherError.Busy);
        try{var worker=new Thread(ReceiveLoop){IsBackground=true,Name="Tether media receive"};if(ExecutionContext.IsFlowSuppressed())worker.Start();else using(ExecutionContext.SuppressFlow())worker.Start();}
        catch{WorkerSlots.Release();throw;}
        heartbeat=Heartbeat();
    }
    internal static async Task<TetherMediaStream> Open(Session session,TetherRoute route,string service,Action released,CancellationToken token)
    {
        ulong handle=0;byte[]? lease=null,secret=null,pin=null;
        try {
            await session.SendControl("media.open",token,new(){{"service",service}}).ConfigureAwait(false);
            using var ready=await session.Control("media.ready",token).ConfigureAwait(false);var root=ready.RootElement;
            lease=Native.Data(root,"lease_id",16);secret=Native.Data(root,"token",32);pin=Native.Data(root,"cert_pin",32);
            var port=root.GetProperty("port").GetUInt16();var maximum=root.GetProperty("max_datagram").GetInt32();
            if(port==0||maximum is <1 or >1200||root.GetProperty("heartbeat_seconds").GetInt32()!=2||root.GetProperty("lease_ttl_seconds").GetInt32()!=5)throw new TetherException(TetherError.Protocol);
            using(var started=Native.Call(new(){{"command","media.client.start"},{"address",route.Host},{"port",port},{"lease_id",lease},{"token",secret},{"cert_pin",pin}}))handle=Native.Handle(started.RootElement);
            using var wait=CancellationTokenSource.CreateLinkedTokenSource(token);wait.CancelAfter(TimeSpan.FromSeconds(10));
            var lastHeartbeat=System.Diagnostics.Stopwatch.StartNew();while(true){wait.Token.ThrowIfCancellationRequested();if(lastHeartbeat.Elapsed>=TimeSpan.FromSeconds(2)){await session.SendControl("media.heartbeat",wait.Token,new(){{"lease_id",lease}}).ConfigureAwait(false);using var alive=await session.Control("media.alive",wait.Token).ConfigureAwait(false);lastHeartbeat.Restart();}using var status=Native.Call(new(){{"command","media.poll"},{"handle",handle}});var state=status.RootElement.GetProperty("state").GetString();
                if(state=="ready"){maximum=Math.Min(maximum,Maximum(status));break;}if(state!="connecting")throw new TetherException(TetherError.MediaUnavailable);await Task.Delay(10,wait.Token).ConfigureAwait(false);}
            var stream=new TetherMediaStream(session,handle,lease,maximum,released);handle=0;lease=null;return stream;
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){throw new TetherException(TetherError.MediaUnavailable);}
        finally{if(secret!=null)CryptographicOperations.ZeroMemory(secret);if(pin!=null)CryptographicOperations.ZeroMemory(pin);if(lease!=null)CryptographicOperations.ZeroMemory(lease);if(handle!=0)CloseHandle(handle);}
    }
    private static int Maximum(NativeResponse status){var n=status.RootElement.GetProperty("max_datagram").GetInt32();return n is>0 and<=1200?n:throw new TetherException(TetherError.Protocol);}
    private NativeResponse Call(string command,byte[]? data=null,int? wait=null)
    {
        var current=Interlocked.Read(ref handle);if(Volatile.Read(ref closed)!=0||current==0)throw new TetherException(TetherError.Closed);
        var fields=new Dictionary<string,object?>{{"command",command},{"handle",(ulong)current}};if(data!=null)fields["data"]=data;if(wait.HasValue)fields["timeout_ms"]=wait.Value;
        try{return Native.Call(fields);}catch when(Volatile.Read(ref closed)!=0){throw new TetherException(TetherError.Closed);}
    }
    private void Poll(){using var reply=Call("media.poll");if(reply.RootElement.GetProperty("state").GetString()!="ready")throw new TetherException(TetherError.MediaUnavailable);Volatile.Write(ref maxDatagram,Math.Min(ceiling,Maximum(reply)));}
    public async Task SendAsync(ReadOnlyMemory<byte> packet,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();Poll();if(packet.Length>MaxDatagram)throw new TetherException(TetherError.Protocol);var copy=packet.ToArray();
        try{using var result=Call("media.send",copy);if(!result.RootElement.GetProperty("accepted").GetBoolean())throw new TetherException(TetherError.MediaUnavailable);}
        catch{await DisposeAsync().ConfigureAwait(false);throw;}finally{CryptographicOperations.ZeroMemory(copy);}
    }
    // One bounded dedicated receiver per handle avoids occupying the shared .NET pool during idle waits.
    // Its permit is held until the thread exits, including while a handle is being retired.
    private void ReceiveLoop()
    {
        try{foreach(var request in requests.GetConsumingEnumerable()){
            try{while(true){if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);using var reply=Call("media.receive_wait",wait:100);var state=reply.RootElement.GetProperty("state").GetString();
                if(state=="pending")continue;if(state!="data")throw new TetherException(TetherError.MediaUnavailable);var data=Native.Data(reply.RootElement);Poll();if(data.Length>MaxDatagram)throw new TetherException(TetherError.Protocol);request.TrySetResult(data);break;}}
            catch(Exception error){request.TrySetException(error is TetherException?error:new TetherException(TetherError.MediaUnavailable));SignalClose();break;}
        }}finally{while(requests.TryTake(out var pending))pending.TrySetException(new TetherException(TetherError.Closed));WorkerSlots.Release();receiverStopped.TrySetResult(true);}
    }
    public async Task<byte[]> ReceiveAsync(CancellationToken token=default)
    {
        if(!await receiving.WaitAsync(0,token).ConfigureAwait(false))throw new TetherException(TetherError.Busy);
        using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,lifetime.Token);using var cancellation=linked.Token.Register(SignalClose);
        try{token.ThrowIfCancellationRequested();if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);var result=new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);if(!requests.TryAdd(result))throw new TetherException(TetherError.Busy);var data=await result.Task.ConfigureAwait(false);token.ThrowIfCancellationRequested();if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);return data;}
        catch(Exception)when(token.IsCancellationRequested){await DisposeAsync().ConfigureAwait(false);throw new OperationCanceledException(token);}
        catch{await DisposeAsync().ConfigureAwait(false);throw;}finally{receiving.Release();}
    }
    public TetherMediaStats Statistics()
    {using var result=Call("media.stats");var r=result.RootElement;return new(r.GetProperty("rtt_ms").GetDouble(),r.GetProperty("bytes_sent").GetUInt64(),r.GetProperty("bytes_received").GetUInt64(),r.GetProperty("packets_sent").GetUInt64(),r.GetProperty("packets_received").GetUInt64(),r.GetProperty("dropped").GetUInt64());}
    private async Task Heartbeat()
    {
        try{while(true){await Task.Delay(TimeSpan.FromSeconds(2),lifetime.Token).ConfigureAwait(false);await session.SendControl("media.heartbeat",lifetime.Token,new(){{"lease_id",lease}}).ConfigureAwait(false);using var reply=await session.Control("media.alive",lifetime.Token).ConfigureAwait(false);Poll();}}
        catch{SignalClose();}
    }
    private static void CloseHandle(ulong value){try{using var reply=Native.Call(new(){{"command","media.close"},{"handle",value}});}catch{}}
    private void SignalClose()
    {
        if(Interlocked.Exchange(ref closed,1)!=0)return;
        var value=Interlocked.Exchange(ref handle,0);if(value>0)CloseHandle((ulong)value); // Native close only signals/wakes; it does not join network workers.
        lifetime.Cancel();requests.CompleteAdding();_ = Task.Run(Cleanup);
    }
    private async Task Cleanup()
    {
        try{try{await session.DisposeAsync().ConfigureAwait(false);}catch{}try{await Task.WhenAll(heartbeat,receiverStopped.Task).ConfigureAwait(false);}catch{}}
        finally{CryptographicOperations.ZeroMemory(lease);try{released();Closed?.Invoke();}finally{closeCompleted.TrySetResult(true);}}
    }
    internal void Abort()=>SignalClose();
    public ValueTask DisposeAsync(){SignalClose();return new ValueTask(closeCompleted.Task);}
}
