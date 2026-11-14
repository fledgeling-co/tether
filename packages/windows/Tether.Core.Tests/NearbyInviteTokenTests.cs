using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Tether.Core.Tests;

/// <summary>The one-time nearby invite token, from the inviting side.
///
/// An invite used to be a line anybody on the local network could compose, and the invited badge was set by the name a peer
/// announced. A device now answers every connection to its invite listener with a fresh 32-byte token, and a host must read
/// that token and echo it; the device repeats it in <c>pair.nearby</c>, so <see cref="NearbyRequest.InviteToken"/> rather
/// than a name is what tells this computer's own invite from anybody's.</summary>
public sealed class NearbyInviteTokenTests
{
    private const string Issued = "Zm9vYmFyMTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1OT1A";

    /// <summary>Answers one connection with <paramref name="challenge"/> and records the line that comes back.</summary>
    private static (TcpListener Listener, Task<string?> Received) Device(string challenge)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var received = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var timeout = new CancellationTokenSource(5000);
            await client.GetStream().WriteAsync(Encoding.UTF8.GetBytes(challenge + "\n"), timeout.Token);
            var buffer = new byte[512];
            var read = await client.GetStream().ReadAsync(buffer, timeout.Token);
            return read == 0 ? null : Encoding.UTF8.GetString(buffer, 0, read).Split('\n')[0];
        });
        return (listener, received);
    }

    private static NearbyPeer PeerFor(TcpListener listener) =>
        new("device", "Field iPhone", "iPhone", null, new[] { "127.0.0.1" }, (ushort)((IPEndPoint)listener.LocalEndpoint).Port);

    [Fact]
    public async Task An_invite_echoes_the_token_the_device_issued_on_that_connection()
    {
        var (listener, received) = Device($"{{\"v\":1,\"app\":\"test.app\",\"tok\":\"{Issued}\"}}");
        try
        {
            var echoed = await TetherNearbyInviteListener.InviteAsync(PeerFor(listener), "test.app", "Studio PC", 7445);
            Assert.Equal(Issued, echoed);
            var line = Assert.IsType<string>(await received);
            Assert.Contains(Issued, line);
            Assert.Contains("7445", line);
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task A_host_that_reads_no_token_sends_no_invite()
    {
        // The defect: a host that never had to read anything could write an invite at any listener it found.
        foreach (var challenge in new[] { "{\"v\":1,\"app\":\"test.app\"}", $"{{\"v\":2,\"app\":\"test.app\",\"tok\":\"{Issued}\"}}",
                                          $"{{\"v\":1,\"app\":\"other.app\",\"tok\":\"{Issued}\"}}", "{\"v\":1,\"app\":\"test.app\",\"tok\":\"short\"}" })
        {
            var (listener, received) = Device(challenge);
            try
            {
                await Assert.ThrowsAsync<TetherException>(() => TetherNearbyInviteListener.InviteAsync(PeerFor(listener), "test.app", "Studio PC", 7445));
                Assert.Null(await received);
            }
            finally { listener.Stop(); }
        }
    }
}
