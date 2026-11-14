# Embed Tether on Windows

The Windows kit supplies `Fledgeling.Tether.Windows` for transport and `Fledgeling.Tether.WinUI` for native client and host controls. Both use the same Rust Noise, pairing and QUIC implementation as the Apple SDK. The current development packages target Windows x64; the host application owns its data, service handlers and codecs.

Build from a Windows x64 MSVC checkout with a supported .NET 10 SDK:

```powershell
./scripts/windows/build.ps1 -Configuration Release -OutputDirectory C:\scratch\tether-sdk
./scripts/windows/verify-packages.ps1 -ArtifactsDirectory C:\scratch\tether-sdk
```

Choose a fresh output directory. The script refuses overwrites, runs fresh managed compilation and tests, builds the WinUI sample, and packages the native DLL and helper. An isolated SDK can be supplied through `-DotNetPath`. The Core library retains a net8.0 compatibility target; the sample and WinUI package use .NET 10. The current native controls use Windows App SDK 2.6.5.

Add `Fledgeling.Tether.Windows` version `0.1.0-preview.4` and `Fledgeling.Tether.WinUI` version `0.1.0-preview.4` to your application, either from the generated `nuget` directory or from the `.nupkg` assets on the [v0.1.0-preview.4 release](https://github.com/fledgeling-co/tether/releases/tag/v0.1.0-preview.4). Both are unlisted packages: put the folder holding them in a `NuGet.config` source and reference them normally — `Fledgeling.Tether.Windows` needs no Rust toolchain, because the Windows x64 `tether_ffi.dll` and `tether.exe` travel inside it. The WinUI update preserves native row identity and selection during status refreshes. The Core package copies `tether_ffi.dll` and `tether.exe` into the application output through its build-transitive target. Missing artifacts fail validation. The packages are unsigned development components; your application supplies its distribution signing and installer.

## Own the workspace for the window lifetime

Use one stable application ID for your product. Construct the store and native controls on the UI thread. Keep these objects in the owning window or application:

```csharp
using Tether;
using Tether.WinUI;

client = new TetherClient("com.example.yourapp");
connections = new TetherConnectionStore(client);
host = new TetherHostController("com.example.yourapp");
window.Content = new TetherWorkspaceView(connections, host);
```

`TetherClientView(connections)` and `TetherHostView(host)` are independently reusable. They provide manual private/cloud pairing, saved host selection, connection status, route editing, leaving, local forgetting, host configuration and client removal. Selecting another host preserves the first host's streams. Host setup is create-only and starts listening only after an explicit action. The host's service profiles map names to fixed loopback targets.

Dispose the connection store and host controller asynchronously when the window closes, then dispose the client:

```csharp
await connections.DisposeAsync();
await host.DisposeAsync();
client.Dispose();
```

## Call a permitted host service

Your application's content UI chooses an authorized service on a selected host. It supplies its own framing and response parser:

```csharp
await using var stream = await connections.OpenServiceAsync(
    hostId, "api", ServiceKind.Tcp);
await stream.SendAsync(requestBytes);
await stream.FinishSendingAsync();
while (await stream.ReceiveAsync() is { } bytes)
{
    // Feed the application's bounded response parser.
}
```

`connections.OpenMediaAsync(hostId, "audio")` selects private/VPN QUIC datagrams. Respect `MaxDatagram`, await `SendAsync`/`ReceiveAsync`, and dispose the media session when finished. Encoded packets and packetization belong to the application. `OpenServiceAsync` with `ServiceKind.Udp` explicitly chooses packets inside the reliable carrier; cloud WebSocket traffic retains ordering and can stall after TCP loss. Tether never switches routes or replays API writes automatically.

Identity and peer records use DPAPI CurrentUser with application-specific entropy, owner-only ACLs and atomic generation checks. Default profile directories are app-scoped. A custom profile directory must satisfy the same private-directory checks. The relay receives neither the private identity nor pairing code. A removed client's access is terminal until it pairs again; an unreachable host retains its saved identity.

The sample in `packages/windows/Tether.Sample.WinUI` demonstrates ownership and cleanup. The public [validation record](VALIDATION.md) describes Release package, runtime and native UI checks. Physical internet operation, another Windows account, ARM64, full screen-reader acceptance and signed end-user distribution need their own validation.
