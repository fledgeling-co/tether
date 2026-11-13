using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Tether;

public enum TetherError { InvalidScope, InvalidRoute, Protocol, Authentication, Revoked, IdentityMismatch, PairingPending, PairingExists, Closed, Busy, Capacity, MediaUnavailable, Unavailable, Storage, ServiceRefused, NearbyRefused, NearbyPaused, NearbyBusy }
public sealed class TetherException(TetherError code) : Exception(MessageFor(code))
{
    public TetherError Code { get; } = code;
    private static string MessageFor(TetherError code) => code switch {
        TetherError.IdentityMismatch => "The host identity changed. Saved trust was kept.",
        TetherError.Revoked => "This device’s permission was revoked at this host.",
        TetherError.Authentication => "The authenticated connection was refused.",
        TetherError.Storage => "Protected storage was unavailable or failed validation.",
        TetherError.PairingPending => "Pairing is pending. Recover it before connecting.",
        TetherError.PairingExists => "Saved trust already exists for this host.",
        TetherError.Busy => "Another operation is in progress.",
        TetherError.Capacity => "This host has no free data channels. Close a stream or retry later.",
        TetherError.MediaUnavailable => "The direct media route is unavailable. Choose the reliable service route explicitly.",
        TetherError.NearbyRefused => "That computer isn't accepting new devices right now.",
        TetherError.NearbyPaused => "That computer declined this device several times. Try again in 10 minutes.",
        TetherError.NearbyBusy => "That computer is already showing another request. Try again in a moment.",
        _ => "The Tether operation could not complete."
    };
}
/// <summary>How a nearby pairing ended. Declined and expired save nothing on either device.</summary>
public abstract record NearbyOutcome { public sealed record Paired(PeerRecord Record) : NearbyOutcome; public sealed record Declined : NearbyOutcome; public sealed record Expired : NearbyOutcome; }
public enum ServiceKind { Tcp, Udp }
public enum ConnectionState { Offline, Connecting, Connected, Reconnecting, Revoked, IdentityMismatch, Pending, Capacity }
public enum LocalForgetResult { LocalTrustRemovedHostUnchanged }
public sealed record HostService(string Id, ServiceKind Kind);
public sealed record HostStatus(IReadOnlyList<HostService> Services);
public sealed record TetherRoute(string Mode, string? Host = null, ushort Port = 0, string? Url = null, string? HostId = null)
{
    public static TetherRoute Direct(string host, ushort port) => new("direct", host, port);
    public static TetherRoute Cloud(string url, string hostId) => new("cloud", Url: url, HostId: hostId);
    internal void Validate(bool allowLoopback)
    {
        if (Mode == "direct" && Host is { Length: > 0 and <= 320 } && Port > 0 && !Host.Contains("://") && !Host.Any(char.IsWhiteSpace)) return;
        if (Mode == "cloud" && Url is { Length: <= 2048 } && Uri.TryCreate(Url, UriKind.Absolute, out var uri)
            && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) && string.IsNullOrEmpty(uri.Query)
            && (uri.Scheme == "wss" || (allowLoopback && uri.Scheme == "ws" && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var ip) && IPAddress.IsLoopback(ip)))
            && HostId is { Length: 52 } && HostId.All(c => c is >= 'a' and <= 'z' or >= '2' and <= '7')) return;
        throw new TetherException(TetherError.InvalidRoute);
    }
}
public sealed record PeerRecord(string AppId, string HostKey, string ClientKey, TetherRoute Route, bool Confirmed, Guid PairingId)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public string Id => HostKey;
    internal void Validate(string expectedApp)
    {
        Scope.Validate(AppId); if (AppId != expectedApp || PairingId == Guid.Empty) throw new TetherException(TetherError.InvalidScope);
        Scope.Key(HostKey); Scope.Key(ClientKey);
    }
}
internal static class Scope
{
    internal static void Validate(string value) { if (string.IsNullOrEmpty(value) || value.Length > 64 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_'))) throw new TetherException(TetherError.InvalidScope); }
    internal static byte[] Key(string value) { try { var b=Convert.FromBase64String(value); if(b.Length!=32 || Convert.ToBase64String(b)!=value) throw new FormatException(); return b; } catch { throw new TetherException(TetherError.Protocol); } }
    internal static string ProfileDirectory(string appId)=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Fledgeling","Tether",FileId(appId));
    internal static string FileId(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
