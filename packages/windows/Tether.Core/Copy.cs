using System.Text.Json;

namespace Tether;

/// <summary>A button as the Rust core describes it.</summary>
public sealed record TetherButtonModel(string Label, bool Enabled);
/// <summary>Six digits for display: two groups, and a version read aloud digit by digit.</summary>
public sealed record TetherCodeModel(string Digits, IReadOnlyList<string> Groups, string Spoken);
/// <summary>The requesting device's nearby sheet. <c>Tone</c> is neutral, success or warning.</summary>
public sealed record TetherNearbyViewModel(string Phase, string Title, string Message, string Tone, string? Note, TetherCodeModel? Code, string? Expiry,
    TetherButtonModel? Primary, TetherButtonModel? Secondary, bool Announce, bool Busy);
/// <summary>The host owner's request sheet.</summary>
public sealed record TetherHostRequestViewModel(string Title, TetherCodeModel Code, string Message, string? Services, string? Note, string Expiry,
    TetherButtonModel Primary, TetherButtonModel Secondary);
/// <summary>A saved host's connection state. <c>Tone</c> is neutral, success, warning or danger.</summary>
public sealed record TetherConnectionStateModel(string State, string Title, string Explanation, string Tone);

/// <summary>The words every Tether screen uses, from the Rust core, so WinUI says what Swift, Compose and the web say.</summary>
public static class TetherCopy
{
    private static string? Text(JsonElement root, string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static TetherButtonModel? Button(JsonElement root, string name) =>
        root.TryGetProperty(name, out var b) && b.ValueKind == JsonValueKind.Object ? new(b.GetProperty("label").GetString() ?? "", b.GetProperty("enabled").GetBoolean()) : null;
    private static TetherCodeModel? Code(JsonElement root) =>
        root.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.Object
            ? new(c.GetProperty("digits").GetString() ?? "", c.GetProperty("groups").EnumerateArray().Select(g => g.GetString() ?? "").ToArray(), c.GetProperty("spoken").GetString() ?? "")
            : null;

    /// <summary>The device's sheet for a nearby pairing phase: checking, code, waiting, connected, declined, expired or failed.</summary>
    public static TetherNearbyViewModel Nearby(string phase, string peer, string device, bool incoming = false, string? code = null, long? remainingMs = null,
        bool canApprove = false, bool hostApproved = false, bool declinedBySelf = false, string? error = null)
    {
        using var r = Native.Call(new() { { "command", "ui.nearby" }, { "phase", phase }, { "peer", peer }, { "device", device }, { "incoming", incoming }, { "code", code },
            { "remainingMs", remainingMs is { } ms ? Math.Max(0, ms) : null }, { "canApprove", canApprove }, { "hostApproved", hostApproved }, { "declinedBySelf", declinedBySelf }, { "error", error } });
        var j = r.RootElement;
        return new(j.GetProperty("phase").GetString() ?? phase, j.GetProperty("title").GetString() ?? "", j.GetProperty("message").GetString() ?? "", j.GetProperty("tone").GetString() ?? "neutral",
            Text(j, "note"), Code(j), Text(j, "expiry"), Button(j, "primary"), Button(j, "secondary"), j.GetProperty("announce").GetBoolean(), j.GetProperty("busy").GetBoolean());
    }

    public static TetherHostRequestViewModel HostRequest(string name, string code, long remainingMs, long shownMs, bool deviceApproved, bool invited, IEnumerable<string> services)
    {
        using var r = Native.Call(new() { { "command", "ui.host_request" }, { "name", name }, { "code", code }, { "remainingMs", Math.Max(0, remainingMs) }, { "shownMs", Math.Max(0, shownMs) },
            { "deviceApproved", deviceApproved }, { "invited", invited }, { "services", services.ToArray() } });
        var j = r.RootElement;
        return new(j.GetProperty("title").GetString() ?? "", Code(j)!, j.GetProperty("message").GetString() ?? "", Text(j, "services"), Text(j, "note"), j.GetProperty("expiry").GetString() ?? "",
            Button(j, "primary")!, Button(j, "secondary")!);
    }

    public static TetherConnectionStateModel ConnectionState(string state)
    {
        using var r = Native.Call(new() { { "command", "ui.connection_state" }, { "state", state } });
        var j = r.RootElement;
        return new(j.GetProperty("state").GetString() ?? state, j.GetProperty("title").GetString() ?? "", j.GetProperty("explanation").GetString() ?? "", j.GetProperty("tone").GetString() ?? "neutral");
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, IReadOnlyDictionary<string, string>> strings = new();
    /// <summary>Fixed copy keyed as in the core's <c>view::strings</c>; a missing key reads as itself.</summary>
    public static string String(string key, string device = "PC") => strings.GetOrAdd(device, d =>
    {
        using var r = Native.Call(new() { { "command", "ui.strings" }, { "device", d } });
        return r.RootElement.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.String).ToDictionary(p => p.Name, p => p.Value.GetString() ?? "");
    }).TryGetValue(key, out var text) ? text : key;

    /// <summary>A plain-language explanation of a failure, naming <paramref name="peer"/>.</summary>
    public static string Message(string code, string peer)
    {
        try { using var r = Native.Call(new() { { "command", "ui.error" }, { "code", code }, { "peer", peer } }); return r.RootElement.GetProperty("message").GetString() ?? ""; }
        catch (TetherException) { return "The pairing didn't finish. Nothing was paired."; }
    }

    public static string Message(TetherError error, string peer) => Message(Code(error), peer);

    /// <summary>A label another device chose, safe to show beside a code.</summary>
    public static string Label(string? raw, string fallback)
    {
        using var r = Native.Call(new() { { "command", "ui.label" }, { "text", raw ?? "" }, { "fallback", fallback } });
        return r.RootElement.GetProperty("text").GetString() ?? fallback;
    }

    /// <summary>The error for a failure code from the core or a host.</summary>
    public static TetherError Error(string? code) => code switch
    {
        "peer_revoked" => TetherError.Revoked, "service_denied" => TetherError.ServiceRefused, "service_capacity" => TetherError.Capacity,
        "media_unavailable" => TetherError.MediaUnavailable, "relay_refused" or "nearby_closed" => TetherError.NearbyRefused, "paused" => TetherError.NearbyPaused,
        "busy" => TetherError.NearbyBusy, "already_paired" => TetherError.PairingExists, "pairing_pending" => TetherError.PairingPending,
        "identity_mismatch" => TetherError.IdentityMismatch, "invalid_code" or "authentication_refused" => TetherError.Authentication, "invalid_route" => TetherError.InvalidRoute,
        _ => TetherError.Protocol,
    };

    /// <summary>The core's name for an error, for looking up its message.</summary>
    public static string Code(TetherError error) => error switch
    {
        TetherError.Revoked => "peer_revoked", TetherError.ServiceRefused => "service_denied", TetherError.Capacity => "service_capacity",
        TetherError.MediaUnavailable => "media_unavailable", TetherError.NearbyRefused => "nearby_closed", TetherError.NearbyPaused => "paused",
        TetherError.NearbyBusy => "busy", TetherError.PairingExists => "already_paired", TetherError.PairingPending => "pairing_pending",
        TetherError.IdentityMismatch => "identity_mismatch", TetherError.Authentication => "invalid_code", TetherError.InvalidRoute => "invalid_route",
        TetherError.Unavailable => "unavailable", _ => "",
    };
}
