using Xunit;
namespace Tether.Core.Tests;

public sealed class StreamOwnershipTests
{
    [Fact]public async Task A_busy_finish_does_not_close_an_owned_send_or_consume_its_fin()
    {
        using var ac=Native.Call(new(){{"command","identity.generate"}});using var bc=Native.Call(new(){{"command","identity.generate"}});using var a=new Identity(ac);using var b=new Identity(bc);
        using var first=Native.Call(new(){{"command","noise.new"},{"identity",a.Handle.Value},{"app","test.stream"},{"role","client"}});using var second=Native.Call(new(){{"command","noise.new"},{"identity",b.Handle.Value},{"app","test.stream"},{"role","host"}});using var an=new NativeHandle(Native.Handle(first.RootElement));using var bn=new NativeHandle(Native.Handle(second.RootElement));
        byte[] Write(ulong handle){using var reply=Native.Call(new(){{"command","noise.write"},{"handle",handle},{"data",Array.Empty<byte>()}});return Native.Data(reply.RootElement);}void Read(ulong handle,byte[] bytes){using var reply=Native.Call(new(){{"command","noise.read"},{"handle",handle},{"data",bytes}});}
        Read(bn.Value,Write(an.Value));Read(an.Value,Write(bn.Value));Read(bn.Value,Write(an.Value));using var finished=Native.Call(new(){{"command","noise.finish"},{"handle",an.Take()}});
        var carrier=new BlockingCarrier();var released=0;var session=new Session(carrier,new(Native.Handle(finished.RootElement)),b.Public,Native.Data(finished.RootElement,"binding",32));await using var stream=new TetherServiceStream(ServiceKind.Tcp,session,()=>released++);
        var send=stream.SendAsync(new byte[]{1});await carrier.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));Assert.Equal(TetherError.Busy,(await Assert.ThrowsAsync<TetherException>(()=>stream.FinishSendingAsync())).Code);Assert.False(carrier.Disposed,carrier.DisposeStack);Assert.Equal(0,released);
        carrier.Release.SetResult(true);await send;await stream.FinishSendingAsync();Assert.False(carrier.Disposed,carrier.DisposeStack);await stream.DisposeAsync();Assert.True(carrier.Disposed);Assert.Equal(1,released);
    }
    private sealed class BlockingCarrier : ICarrier
    {
        internal readonly TaskCompletionSource<bool> Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);internal bool Disposed;internal string? DisposeStack;
        public async Task SendAsync(byte[] bytes,CancellationToken token){Entered.TrySetResult(true);await Release.Task.WaitAsync(token);}
        public Task<byte[]> ReceiveAsync(CancellationToken token)=>throw new NotSupportedException("This fixture controls an outbound operation only.");
        public ValueTask DisposeAsync(){DisposeStack=Environment.StackTrace;Disposed=true;Release.TrySetResult(true);return ValueTask.CompletedTask;}
    }
}
