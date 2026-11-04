using System.Diagnostics;
using Xunit;
namespace Tether.Core.Tests;

public sealed class HostOwnershipTests
{
    [Fact]public async Task Closed_stdout_does_not_release_restart_until_the_actual_owned_process_exits()
    {
        var root=Path.Combine(Path.GetTempPath(),"tether-retirement-"+Guid.NewGuid().ToString("N"));await using var host=new TetherHostController("test.retirement",Path.Combine(root,"unused.profile"),Path.Combine(AppContext.BaseDirectory,"tether-helper-fixture.exe"));using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));var token=timeout.Token;
        await host.StartAsync(HostRoute.Direct("127.0.0.1",12345),token);using var first=Process.GetProcessById(host.OwnedProcessId!.Value);while(host.State!=HostRunState.Stopping){token.ThrowIfCancellationRequested();await Task.Delay(5,token);}Assert.False(first.HasExited);await host.StartAsync(HostRoute.Direct("127.0.0.1",12345),token);Assert.True(first.HasExited);Assert.NotEqual(first.Id,host.OwnedProcessId);await host.StopAsync();Assert.Null(host.OwnedProcessId);
    }
}
