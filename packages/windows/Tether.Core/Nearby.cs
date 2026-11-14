using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Tether;

/// <summary>Bonjour types shared with the Apple and Android kits: hosts announce their direct port; devices announce an invite listener.</summary>
public static class NearbyService { public const string Host = "_tether._tcp"; public const string Device = "_tether-dev._tcp"; }

/// <summary>Something announcing this app on the local network. Its name is a label shown beside the code, never trusted on its own.</summary>
public sealed record NearbyPeer(string Id, string Name, string Kind, string? HostKey, IReadOnlyList<string> Addresses, ushort Port);

/// <summary>An invitation a host sent to this device: connect to this route and pair. <paramref name="Token"/> is the
/// one-time token this device issued on the connection the invite arrived over, repeated in <c>pair.nearby</c> so the
/// inviting computer can tell this device's request from any other.</summary>
public sealed record NearbyInvite(TetherRoute Route, string HostName, string Token);

/// <summary>Windows DNS-SD (dnsapi.dll, Windows 10 and later). Each call is one bounded query; callers repeat browsing.</summary>
internal static class DnsSd
{
    internal const uint Version1 = 1, RequestPending = 9506, Success = 0;
    [StructLayout(LayoutKind.Sequential)] internal struct Cancel { public IntPtr Reserved; }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void BrowseCallback(uint status, IntPtr context, IntPtr records);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void ResolveCallback(uint status, IntPtr context, IntPtr instance);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate void RegisterCallback(uint status, IntPtr context, IntPtr instance);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct BrowseRequest { public uint Version; public uint InterfaceIndex; public string QueryName; public BrowseCallback Callback; public IntPtr Context; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct ResolveRequest { public uint Version; public uint InterfaceIndex; public string QueryName; public ResolveCallback Callback; public IntPtr Context; }
    [StructLayout(LayoutKind.Sequential)] internal struct RegisterRequest { public uint Version; public uint InterfaceIndex; public IntPtr Instance; public RegisterCallback Callback; public IntPtr Context; public IntPtr Credentials; public int UnicastEnabled; }
    [StructLayout(LayoutKind.Sequential)] internal struct Instance { public IntPtr InstanceName, HostName, Ip4, Ip6; public ushort Port, Priority, Weight; public uint PropertyCount; public IntPtr Keys, Values; public uint InterfaceIndex; }
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)] internal static extern uint DnsServiceBrowse(ref BrowseRequest request, ref Cancel cancel);
    [DllImport("dnsapi.dll")] internal static extern uint DnsServiceBrowseCancel(ref Cancel cancel);
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)] internal static extern uint DnsServiceResolve(ref ResolveRequest request, ref Cancel cancel);
    [DllImport("dnsapi.dll")] internal static extern uint DnsServiceResolveCancel(ref Cancel cancel);
    [DllImport("dnsapi.dll")] internal static extern void DnsServiceFreeInstance(IntPtr instance);
    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)] internal static extern IntPtr DnsServiceConstructInstance(string name, string host, IntPtr ip4, IntPtr ip6, ushort port, ushort priority, ushort weight, uint count, string[] keys, string[] values);
    [DllImport("dnsapi.dll")] internal static extern uint DnsServiceRegister(ref RegisterRequest request, ref Cancel cancel);
    [DllImport("dnsapi.dll")] internal static extern uint DnsServiceDeRegister(ref RegisterRequest request, IntPtr cancel);
    [DllImport("dnsapi.dll")] internal static extern void DnsRecordListFree(IntPtr records, int type);
    internal const ushort TypePtr = 12;
    internal static string Label(string? raw, string fallback) => TetherCopy.Label(raw, fallback);

    /// <summary>The PTR names from a DNS_RECORD list: the instance names a browse found.</summary>
    internal static List<string> Pointers(IntPtr record)
    {
        var names = new List<string>();
        for (var current = record; current != IntPtr.Zero; current = Marshal.ReadIntPtr(current))
        {
            var type = (ushort)Marshal.ReadInt16(current, 2 * IntPtr.Size);
            // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved, then Data (pointer-aligned).
            var dataOffset = 2 * IntPtr.Size + 4 + 4 + 4 + 4; dataOffset = (dataOffset + IntPtr.Size - 1) / IntPtr.Size * IntPtr.Size;
            if (type == TypePtr && Marshal.PtrToStringUni(Marshal.ReadIntPtr(current, dataOffset)) is { Length: > 0 and < 512 } name) names.Add(name);
        }
        return names;
    }
}

/// <summary>Lists hosts (or, on a host, devices) announcing this app on the local network.</summary>
public sealed class TetherNearbyBrowser : IDisposable
{
    public string AppId { get; }
    public IReadOnlyList<NearbyPeer> Peers { get { lock (gate) return found.Values.Select(v => v.Peer).OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).ToArray(); } }
    public event Action? Changed;
    private readonly string serviceType; private readonly object gate = new(); private readonly Dictionary<string, (NearbyPeer Peer, DateTimeOffset Seen)> found = new();
    private readonly CancellationTokenSource lifetime = new(); private Task? loop;
    public TetherNearbyBrowser(string appId, string serviceType = NearbyService.Host) { Scope.Validate(appId); AppId = appId; this.serviceType = serviceType; }

    public void Start() { if (loop != null || !OperatingSystem.IsWindows()) return; loop = Task.Run(() => Run(lifetime.Token)); }

    private async Task Run(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            foreach (var name in await Browse(token)) _ = Resolve(name, token);
            // Forget what stopped answering, so a computer that quit leaves the list.
            lock (gate) foreach (var stale in found.Where(f => DateTimeOffset.UtcNow - f.Value.Seen > TimeSpan.FromSeconds(20)).Select(f => f.Key).ToArray()) { found.Remove(stale); Changed?.Invoke(); }
            try { await Task.Delay(TimeSpan.FromSeconds(3), token); } catch (OperationCanceledException) { return; }
        }
    }

    private Task<List<string>> Browse(CancellationToken token)
    {
        var completion = new TaskCompletionSource<List<string>>(TaskCreationOptions.RunContinuationsAsynchronously);
        DnsSd.BrowseCallback callback = (status, _, records) =>
        {
            try { completion.TrySetResult(status == DnsSd.Success && records != IntPtr.Zero ? DnsSd.Pointers(records) : new List<string>()); }
            finally { if (records != IntPtr.Zero) DnsSd.DnsRecordListFree(records, 1); }
        };
        var request = new DnsSd.BrowseRequest { Version = DnsSd.Version1, QueryName = serviceType + ".local", Callback = callback };
        var cancel = new DnsSd.Cancel();
        if (DnsSd.DnsServiceBrowse(ref request, ref cancel) != DnsSd.RequestPending) return Task.FromResult(new List<string>());
        return Finish(completion, () => DnsSd.DnsServiceBrowseCancel(ref cancel), callback, token);
    }

    private static async Task<List<string>> Finish(TaskCompletionSource<List<string>> completion, Action cancel, Delegate keepAlive, CancellationToken token)
    {
        try { return await completion.Task.WaitAsync(TimeSpan.FromSeconds(2.5), token); }
        catch { cancel(); return new List<string>(); }
        finally { GC.KeepAlive(keepAlive); }
    }

    private async Task Resolve(string name, CancellationToken token)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        DnsSd.ResolveCallback callback = (status, _, pointer) =>
        {
            try { if (status == DnsSd.Success && pointer != IntPtr.Zero) Accept(name, Marshal.PtrToStructure<DnsSd.Instance>(pointer)); }
            finally { if (pointer != IntPtr.Zero) DnsSd.DnsServiceFreeInstance(pointer); completion.TrySetResult(true); }
        };
        var request = new DnsSd.ResolveRequest { Version = DnsSd.Version1, QueryName = name, Callback = callback };
        var cancel = new DnsSd.Cancel();
        if (DnsSd.DnsServiceResolve(ref request, ref cancel) != DnsSd.RequestPending) return;
        try { await completion.Task.WaitAsync(TimeSpan.FromSeconds(3), token); } catch { DnsSd.DnsServiceResolveCancel(ref cancel); } finally { GC.KeepAlive(callback); }
    }

    private void Accept(string name, DnsSd.Instance instance)
    {
        var txt = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < instance.PropertyCount && i < 32; i++)
        {
            var name_ = Marshal.PtrToStringUni(Marshal.ReadIntPtr(instance.Keys, i * IntPtr.Size)); var value = Marshal.PtrToStringUni(Marshal.ReadIntPtr(instance.Values, i * IntPtr.Size));
            if (name_ != null) txt[name_] = value ?? "";
        }
        if (!txt.TryGetValue("app", out var app) || app != AppId) return;
        var addresses = new List<string>();
        if (txt.TryGetValue("addr", out var hinted)) addresses.AddRange(hinted.Split(',').Where(a => IPAddress.TryParse(a, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork).Take(8));
        if (instance.Ip4 != IntPtr.Zero) addresses.Add(new IPAddress((uint)Marshal.ReadInt32(instance.Ip4)).ToString());
        var port = txt.TryGetValue("port", out var p) && ushort.TryParse(p, out var parsed) && parsed > 0 ? parsed : instance.Port;
        string? hostKey = txt.TryGetValue("key", out var k) && k.Length == 44 ? k : null;
        var label = name.Split('.')[0];
        var peer = new NearbyPeer(name, DnsSd.Label(txt.GetValueOrDefault("name") ?? label, label), DnsSd.Label(txt.GetValueOrDefault("kind"), "Computer"), hostKey, addresses.Distinct().ToArray(), port);
        lock (gate) found[name] = (peer, DateTimeOffset.UtcNow);
        Changed?.Invoke();
    }

    /// <summary>The first announced address that accepts a TCP connection within a moment.</summary>
    public static async Task<TetherRoute> RouteAsync(NearbyPeer peer, CancellationToken token = default)
    {
        foreach (var address in peer.Addresses)
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(1500);
            try { await client.ConnectAsync(IPAddress.Parse(address), peer.Port, timeout.Token); return TetherRoute.Direct(address, peer.Port); } catch when (!token.IsCancellationRequested) { }
        }
        throw new TetherException(TetherError.InvalidRoute);
    }

    public void Dispose() { lifetime.Cancel(); }
}

/// <summary>Registers one DNS-SD service until disposed.</summary>
public sealed class TetherNearbyAnnouncement : IDisposable
{
    private DnsSd.RegisterRequest request; private readonly DnsSd.RegisterCallback callback = (_, _, _) => { }; private IntPtr instance; private int closed;
    public TetherNearbyAnnouncement(string appId, string name, string kind, ushort port, string serviceType = NearbyService.Host, string? hostKey = null, IEnumerable<string>? addresses = null)
    {
        Scope.Validate(appId); if (!OperatingSystem.IsWindows()) throw new TetherException(TetherError.Unavailable);
        var label = DnsSd.Label(name, "Computer");
        var keys = new List<string> { "app", "name", "kind", "port" }; var values = new List<string> { appId, label, DnsSd.Label(kind, "Computer"), port.ToString() };
        if (hostKey is { Length: 44 }) { keys.Add("key"); values.Add(hostKey); }
        var listed = string.Join(",", (addresses ?? LocalAddresses()).Take(6)); if (listed.Length > 0) { keys.Add("addr"); values.Add(listed); }
        instance = DnsSd.DnsServiceConstructInstance(label + "." + serviceType + ".local", Dns.GetHostName() + ".local", IntPtr.Zero, IntPtr.Zero, port, 0, 0, (uint)keys.Count, keys.ToArray(), values.ToArray());
        if (instance == IntPtr.Zero) throw new TetherException(TetherError.Unavailable);
        request = new DnsSd.RegisterRequest { Version = DnsSd.Version1, Instance = instance, Callback = callback };
        var cancel = new DnsSd.Cancel();
        if (DnsSd.DnsServiceRegister(ref request, ref cancel) != DnsSd.RequestPending) { DnsSd.DnsServiceFreeInstance(instance); instance = IntPtr.Zero; throw new TetherException(TetherError.Unavailable); }
    }

    /// <summary>This computer's IPv4 addresses on interfaces that are up, without loopback or link-local.</summary>
    public static IEnumerable<string> LocalAddresses() =>
        System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
            .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.ToString().StartsWith("169.254.", StringComparison.Ordinal)).Select(a => a.ToString()).Distinct();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref closed, 1) != 0 || instance == IntPtr.Zero) return;
        DnsSd.DnsServiceDeRegister(ref request, IntPtr.Zero); GC.KeepAlive(callback);
        DnsSd.DnsServiceFreeInstance(instance); instance = IntPtr.Zero;
    }
}

/// <summary>The one-time invite token, minted and checked by the shared Rust core so every kit agrees on what a valid
/// invite is. Nothing here decides trust: the code comparison does.</summary>
internal static class NearbyInviteToken
{
    internal static string Mint()
    {
        using var r = Native.Call(new() { { "command", "discovery.invite_token" } });
        return r.RootElement.GetProperty("token").GetString() ?? throw new TetherException(TetherError.Protocol);
    }

    internal static byte[] Challenge(string appId, string token)
    {
        using var r = Native.Call(new() { { "command", "discovery.challenge" }, { "app", appId }, { "token", token } });
        return Line(r.RootElement.GetProperty("line").GetString());
    }

    internal static string? ReadChallenge(string appId, string line)
    {
        try
        {
            using var r = Native.Call(new() { { "command", "discovery.read_challenge" }, { "app", appId }, { "line", line } });
            return r.RootElement.GetProperty("token").ValueKind == JsonValueKind.String ? r.RootElement.GetProperty("token").GetString() : null;
        }
        catch { return null; }
    }

    internal static byte[] Invite(string appId, string hostName, ushort port, string token)
    {
        using var r = Native.Call(new() { { "command", "discovery.invite" }, { "app", appId }, { "name", hostName }, { "port", (int)port }, { "token", token } });
        return Line(r.RootElement.GetProperty("line").GetString());
    }

    internal static ReadInviteResult? ReadInvite(string appId, string line, string remote, string issued)
    {
        try
        {
            using var r = Native.Call(new() { { "command", "discovery.read_invite" }, { "app", appId }, { "line", line }, { "remote", remote }, { "token", issued } });
            var invite = r.RootElement.GetProperty("invite");
            if (invite.ValueKind != JsonValueKind.Object) return null;
            var port = invite.GetProperty("port").GetInt32();
            if (port is < 1 or > 65535) return null;
            return new ReadInviteResult(invite.GetProperty("host").GetString() ?? remote, (ushort)port,
                                        invite.TryGetProperty("name", out var name) ? name.GetString() ?? "Computer" : "Computer");
        }
        catch { return null; }
    }

    private static byte[] Line(string? text)
    {
        if (text is null) throw new TetherException(TetherError.Protocol);
        return Encoding.UTF8.GetBytes(text).Concat(new byte[] { 10 }).ToArray();
    }

    internal readonly record struct ReadInviteResult(string Host, ushort Port, string Name);
}

/// <summary>This device's invite listener, announced while Add a computer is open. An invite only starts an ordinary nearby pairing to
/// the inviting address; the code comparison still decides trust.
///
/// Every connection is answered with a fresh one-time token, and an invite is read only when it echoes that token, so an
/// invite has to come from something that opened a connection here and read a 32-byte secret off it and each token admits
/// one invite. It does not identify the inviting computer: anything on the local network can open that connection.</summary>
public sealed class TetherNearbyInviteListener : IDisposable
{
    private readonly TcpListener listener = new(IPAddress.Any, 0); private readonly TetherNearbyAnnouncement announcement; private readonly CancellationTokenSource lifetime = new();
    public TetherNearbyInviteListener(string appId, string deviceName, string deviceKind, Action<NearbyInvite> onInvite)
    {
        Scope.Validate(appId); listener.Start();
        announcement = new TetherNearbyAnnouncement(appId, deviceName, deviceKind, (ushort)((IPEndPoint)listener.LocalEndpoint).Port, NearbyService.Device);
        _ = Task.Run(async () =>
        {
            while (!lifetime.IsCancellationRequested)
            {
                TcpClient client; try { client = await listener.AcceptTcpClientAsync(lifetime.Token); } catch { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            using var timeout = new CancellationTokenSource(3000);
                            if (client.Client.RemoteEndPoint is not IPEndPoint remote) return;
                            // The challenge goes out first: an invite that does not come back carrying this token is
                            // not one this device asked for, whatever name it announces.
                            var token = NearbyInviteToken.Mint();
                            var challenge = NearbyInviteToken.Challenge(appId, token);
                            await client.GetStream().WriteAsync(challenge, timeout.Token);
                            var buffer = new byte[512]; var read = await client.GetStream().ReadAsync(buffer, timeout.Token);
                            var line = Encoding.UTF8.GetString(buffer, 0, read).Split('\n')[0];
                            if (NearbyInviteToken.ReadInvite(appId, line, remote.Address.MapToIPv4().ToString(), token) is not { } invite) return;
                            onInvite(new NearbyInvite(TetherRoute.Direct(invite.Host, invite.Port), invite.Name, token));
                        }
                        catch { }
                    }
                });
            }
        });
    }

    /// <summary>Sent by a host to a device it found: "pair with me at this port". Returns the one-time token that device
    /// issued on this connection; hold it, because the request carrying it is the one that answered this invite.</summary>
    public static async Task<string> InviteAsync(NearbyPeer peer, string appId, string hostName, ushort port, CancellationToken token = default)
    {
        Scope.Validate(appId); Exception? last = null;
        foreach (var address in peer.Addresses)
        {
            try
            {
                using var client = new TcpClient(AddressFamily.InterNetwork); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(3000);
                await client.ConnectAsync(IPAddress.Parse(address), peer.Port, timeout.Token);
                var buffer = new byte[512]; var read = await client.GetStream().ReadAsync(buffer, timeout.Token);
                var challenge = Encoding.UTF8.GetString(buffer, 0, read).Split('\n')[0];
                if (NearbyInviteToken.ReadChallenge(appId, challenge) is not { } issued) throw new TetherException(TetherError.Protocol);
                await client.GetStream().WriteAsync(NearbyInviteToken.Invite(appId, hostName, port, issued), timeout.Token);
                return issued;
            }
            catch (Exception e) when (!token.IsCancellationRequested) { last = e; }
        }
        throw last is TetherException refusal ? refusal : new TetherException(TetherError.InvalidRoute);
    }

    public void Dispose() { lifetime.Cancel(); listener.Stop(); announcement.Dispose(); }
}
