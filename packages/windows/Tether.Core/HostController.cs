using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tether;

public enum HostRunState { Stopped,Starting,Listening,RelayConnected,RelayDisconnected,Failed,Stopping }
public sealed record HostServiceProfile(string Id,ServiceKind Kind,string LoopbackAddress,ushort Port)
{
    internal string Argument {get{Scope.Validate(Id);if(!IPAddress.TryParse(LoopbackAddress,out var address)||!IPAddress.IsLoopback(address)||Port==0)throw new TetherException(TetherError.InvalidRoute);return Id+"="+(Kind==ServiceKind.Tcp?"tcp":"udp")+"://"+(address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6?"["+address+"]":address.ToString())+":"+Port;}}
}
public sealed record HostRoute(string Mode,string? Address=null,ushort Port=0,string? RelayUrl=null)
{
    public static HostRoute Direct(string address,ushort port)=>new("direct",address,port);
    public static HostRoute Cloud(string relayUrl)=>new("cloud",RelayUrl:relayUrl);
    internal IEnumerable<string> Arguments(bool testing)
    {
        if(Mode=="direct"&&IPAddress.TryParse(Address,out var address)&&Port>0)return new[]{"--direct",(address.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6?"["+address+"]":address.ToString())+":"+Port};
        if(Mode=="cloud"&&Uri.TryCreate(RelayUrl,UriKind.Absolute,out var url)&&url.UserInfo.Length==0&&url.Query.Length==0&&url.Fragment.Length==0&&url.AbsoluteUri.Length<=2048&&(url.Scheme=="wss"||(testing&&url.Scheme=="ws"&&IPAddress.TryParse(url.Host.Trim('[',']'),out var ip)&&IPAddress.IsLoopback(ip))))return testing?new[]{"--relay",url.AbsoluteUri,"--allow-loopback-dev"}:new[]{"--relay",url.AbsoluteUri};
        throw new TetherException(TetherError.InvalidRoute);
    }
}
public sealed record HostClient(string Id,IReadOnlyList<string> Services,int? ActiveSessions,bool? RecentlySeen,long? LastSeenUnixMs);
public sealed record PairingWindow(string Code,DateTimeOffset ExpiresAt,int AttemptsRemaining);
/// <summary>An app-owned helper and private inherited pipes; stdout is parsed and never logged.</summary>
public sealed class TetherHostController : INotifyPropertyChanged,IAsyncDisposable
{
    public string AppId {get;}public string ProfilePath {get;}
    public HostRunState State {get;private set;}=HostRunState.Stopped;
    public string? HostId {get;private set;}public string? ListeningAddress {get;private set;}
    public IReadOnlyList<HostService> Services {get;private set;}=Array.Empty<HostService>();
    public IReadOnlyList<HostClient> Clients {get;private set;}=Array.Empty<HostClient>();
    public PairingWindow? Pairing {get;private set;}
    public event PropertyChangedEventHandler? PropertyChanged;
    private readonly string helper;private readonly bool testing;private readonly SynchronizationContext? context;
    private readonly SemaphoreSlim mutation=new(1),writing=new(1),requestSlots=new(8);private readonly ConcurrentDictionary<Guid,PendingRequest> requests=new();private sealed record PendingRequest(long Epoch,TaskCompletionSource<JsonElement> Completion);private readonly object ownerState=new();
    private Process? process;private CancellationTokenSource? lifetime;private Task<bool> retirement=Task.FromResult(true);private long epoch;private int closed;private readonly CancellationTokenSource controllerLifetime=new();
    public TetherHostController(string appId,string? profilePath=null,string? helperPath=null,bool allowInsecureLoopbackForTesting=false)
    {
        Scope.Validate(appId);AppId=appId;context=SynchronizationContext.Current;testing=allowInsecureLoopbackForTesting;
        ProfilePath=Path.GetFullPath(profilePath??Path.Combine(Scope.ProfileDirectory(appId),"host","host.dpapi"));
        helper=Path.GetFullPath(helperPath??Path.Combine(AppContext.BaseDirectory,"tether.exe"));
        if(!File.Exists(helper)||!helper.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))throw new TetherException(TetherError.Unavailable);
    }
    internal int? OwnedProcessId{get{lock(ownerState)return process?.Id;}}
    private void EnsureOpen(){if(Volatile.Read(ref closed)!=0)throw new TetherException(TetherError.Closed);}
    private bool Running{get{lock(ownerState)return process is{} p&&!p.HasExited&&State is not(HostRunState.Failed or HostRunState.Stopped);}}
    private void ClearPresence(){Clients=Clients.Select(c=>c with{ActiveSessions=null,RecentlySeen=null,LastSeenUnixMs=null}).ToArray();}
    private void Changed(){if(context!=null&&context!=SynchronizationContext.Current)context.Post(_=>PropertyChanged?.Invoke(this,new(null)),null);else PropertyChanged?.Invoke(this,new(null));}
    private ProcessStartInfo StartInfo(IEnumerable<string> arguments,bool stdin=false)
    {EnsureOpen();var info=new ProcessStartInfo(helper){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=stdin,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};info.Environment.Clear();foreach(var name in new[]{"SystemRoot","WINDIR","TEMP","TMP","USERPROFILE","LOCALAPPDATA","APPDATA","PROGRAMDATA"})if(Environment.GetEnvironmentVariable(name)is{} value)info.Environment[name]=value;foreach(var argument in arguments)info.ArgumentList.Add(argument);return info;}
    private async Task<byte[]> Execute(IEnumerable<string> arguments,CancellationToken token)
    {
        using var p=new Process{StartInfo=StartInfo(arguments)};
        try{if(!p.Start())throw new TetherException(TetherError.Unavailable);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,controllerLifetime.Token);using var d=Deadline.Start(linked.Token);var drain=Drain(p.StandardError.BaseStream,d.Token);var reader=new Lines(p.StandardOutput.BaseStream,262144);var first=await reader.Read(d.Token);if(first==null)throw new TetherException(TetherError.Protocol);if(await reader.Read(d.Token)!=null)throw new TetherException(TetherError.Protocol);await p.WaitForExitAsync(d.Token).ConfigureAwait(false);await drain;if(p.ExitCode!=0){CryptographicOperations.ZeroMemory(first);throw new TetherException(TetherError.Unavailable);}return first;}
        catch{TryKill(p);if(token.IsCancellationRequested)throw new OperationCanceledException(token);throw new TetherException(TetherError.Unavailable);}
    }
    private static void TryKill(Process p){try{if(!p.HasExited)p.Kill(entireProcessTree:true);}catch(InvalidOperationException){}}
    private string[] Scoped(string command)=>new[]{"host",command,"--config",ProfilePath,"--expected-app",AppId};
    public async Task InitializeAsync(IReadOnlyList<HostServiceProfile> services,CancellationToken token=default)
    {
        if(!await mutation.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try{EnsureOpen();if(process!=null||services.Count is <1 or >32||services.Select(s=>s.Id).Distinct(StringComparer.Ordinal).Count()!=services.Count)throw new TetherException(TetherError.InvalidScope);PrivateFiles.PrepareDirectory(Path.GetDirectoryName(ProfilePath)!);
            var arguments=new List<string>{"host","init","--config",ProfilePath,"--app",AppId};foreach(var service in services){arguments.Add("--service");arguments.Add(service.Argument);}
            // Init is create-only. It emits no secret-bearing output and never resets a profile.
            using var p=new Process{StartInfo=StartInfo(arguments)};if(!p.Start())throw new TetherException(TetherError.Unavailable);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,controllerLifetime.Token);using var d=Deadline.Start(linked.Token);var a=Drain(p.StandardOutput.BaseStream,d.Token);var b=Drain(p.StandardError.BaseStream,d.Token);try{await p.WaitForExitAsync(d.Token).ConfigureAwait(false);await Task.WhenAll(a,b);if(p.ExitCode!=0)throw new TetherException(TetherError.Storage);}finally{if(!p.HasExited)p.Kill(entireProcessTree:true);}await InspectAsync(token);
        }finally{mutation.Release();}
    }
    public async Task InspectAsync(CancellationToken token=default)
    {var data=await Execute(Scoped("inspect"),token);try{using var value=JsonDocument.Parse(data);ParseInspection(value.RootElement);}finally{CryptographicOperations.ZeroMemory(data);}}
    private void ParseInspection(JsonElement root)
    {
        if(root.GetProperty("app_id").GetString()!=AppId)throw new TetherException(TetherError.InvalidScope);var id=root.GetProperty("host_id").GetString();if(!ValidHostId(id))throw new TetherException(TetherError.Protocol);
        var source=root.GetProperty("services");if(source.ValueKind!=JsonValueKind.Array||source.GetArrayLength()>32)throw new TetherException(TetherError.Protocol);var services=new List<HostService>();
        foreach(var entry in source.EnumerateArray()){var name=entry.GetProperty("id").GetString()??throw new TetherException(TetherError.Protocol);Scope.Validate(name);var kind=entry.GetProperty("kind").GetString()switch{"tcp"=>ServiceKind.Tcp,"udp"=>ServiceKind.Udp,_=>throw new TetherException(TetherError.Protocol)};if(services.Any(s=>s.Id==name))throw new TetherException(TetherError.Protocol);services.Add(new(name,kind));}HostId=id;Services=services;Changed();
    }
    private static bool ValidHostId(string? id)=>id is{Length:52}&&id.All(c=>c is>='a'and<='z'or>='2'and<='7');
    public async Task StartAsync(HostRoute route,CancellationToken token=default)
    {
        if(!await mutation.WaitAsync(0,token))throw new TetherException(TetherError.Busy);
        try {
            EnsureOpen();Task<bool> retiring;lock(ownerState)retiring=retirement;if(!await retiring.WaitAsync(token))throw new TetherException(TetherError.Unavailable);lock(ownerState)if(process!=null)throw new TetherException(TetherError.Busy);lifetime?.Cancel();lifetime?.Dispose();lifetime=null;var arguments=Scoped("run").ToList();arguments.AddRange(route.Arguments(testing));arguments.AddRange(new[]{"--managed-stdin","--status-json"});await InspectAsync(token);EnsureOpen();
            long current;var source=new CancellationTokenSource();var p=new Process{StartInfo=StartInfo(arguments,true)};var readiness=new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock(ownerState){EnsureOpen();current=++epoch;if(!p.Start()){p.Dispose();source.Dispose();throw new TetherException(TetherError.Unavailable);}process=p;lifetime=source;State=HostRunState.Starting;ListeningAddress=null;}Changed();_ = ReadEvents(p,current,readiness,source.Token);_ = Drain(p.StandardError.BaseStream,source.Token);
            using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,controllerLifetime.Token);using var d=Deadline.Start(linked.Token);try{await readiness.Task.WaitAsync(d.Token);}catch{await StopCore();throw new TetherException(TetherError.Unavailable);}await RefreshClientsAsync(token);
        }finally{mutation.Release();}
    }
    private async Task ReadEvents(Process p,long current,TaskCompletionSource<bool> readiness,CancellationToken token)
    {
        try {
            var reader=new Lines(p.StandardOutput.BaseStream,262144);while(await reader.Read(token)is{} bytes){try{using var doc=JsonDocument.Parse(bytes);var root=doc.RootElement;var kind=root.GetProperty("event").GetString();lock(ownerState){if(current!=epoch)return;
                if(kind=="reply") {if(!Guid.TryParseExact(root.GetProperty("request_id").GetString(),"D",out var id))throw new TetherException(TetherError.Protocol);if(requests.TryRemove(id,out var waiter)){if(root.GetProperty("ok").ValueKind==JsonValueKind.True)waiter.Completion.TrySetResult(root.GetProperty("payload").Clone());else waiter.Completion.TrySetException(new TetherException(TetherError.Protocol));}}
                else if(kind=="listening"){var address=root.GetProperty("address").GetString();if(address==null||!IPEndPoint.TryParse(address,out var endpoint)||endpoint.Port==0)throw new TetherException(TetherError.Protocol);ListeningAddress=address;State=HostRunState.Listening;readiness.TrySetResult(true);Changed();}
                else if(kind=="registered"){var id=root.GetProperty("id").GetString();if(!ValidHostId(id)||id!=HostId)throw new TetherException(TetherError.IdentityMismatch);State=HostRunState.RelayConnected;readiness.TrySetResult(true);Changed();}
                else if(kind=="disconnected"){State=HostRunState.RelayDisconnected;Pairing=null;ClearPresence();Changed();}else throw new TetherException(TetherError.Protocol);}
            }finally{CryptographicOperations.ZeroMemory(bytes);}}
        }catch(OperationCanceledException)when(token.IsCancellationRequested){}catch{}
        finally {var changed=false;lock(ownerState){if(current==epoch&&ReferenceEquals(process,p)){Pairing=null;ClearPresence();State=HostRunState.Stopping;readiness.TrySetException(new TetherException(TetherError.Unavailable));foreach(var item in requests.Where(i=>i.Value.Epoch==current).ToArray())if(requests.TryRemove(item.Key,out var waiter))waiter.Completion.TrySetException(new TetherException(TetherError.Unavailable));if(retirement.IsCompleted)retirement=RetireProcess(p,current,true);changed=true;}}if(changed)Changed();}
    }
    private async Task<JsonElement> Request(string command,string? clientId,CancellationToken token)
    {
        EnsureOpen();if(!await requestSlots.WaitAsync(0,token))throw new TetherException(TetherError.Busy);var id=Guid.NewGuid();var waiter=new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);byte[]? bytes=null;
        try {
            Process p;lock(ownerState){EnsureOpen();p=process??throw new TetherException(TetherError.Unavailable);if(p.HasExited||State is HostRunState.Failed or HostRunState.Stopped or HostRunState.Stopping)throw new TetherException(TetherError.Unavailable);if(command=="pair-code"&&State is not(HostRunState.Listening or HostRunState.RelayConnected))throw new TetherException(TetherError.Unavailable);if(!requests.TryAdd(id,new(epoch,waiter)))throw new TetherException(TetherError.Busy);}
            var value=new Dictionary<string,object?>{{"v",1},{"request_id",id.ToString("D")},{"command",command},{"expected_app",AppId}};if(clientId!=null)value["client_id"]=clientId;bytes=JsonSerializer.SerializeToUtf8Bytes(value);
            if(bytes.Length>2048)throw new TetherException(TetherError.Protocol);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,controllerLifetime.Token);using var d=Deadline.Start(linked.Token);await writing.WaitAsync(d.Token);try{await p.StandardInput.BaseStream.WriteAsync(bytes,d.Token);await p.StandardInput.BaseStream.WriteAsync(new byte[]{10},d.Token);await p.StandardInput.BaseStream.FlushAsync(d.Token);}finally{writing.Release();}return await waiter.Task.WaitAsync(d.Token);
        }catch(OperationCanceledException){if(token.IsCancellationRequested)throw;throw new TetherException(TetherError.Unavailable);}finally{requests.TryRemove(id,out _);requestSlots.Release();if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
    }
    public async Task<PairingWindow> OpenPairingWindowAsync(CancellationToken token=default)
    {if(!await mutation.WaitAsync(0,token))throw new TetherException(TetherError.Busy);try{if(State is not(HostRunState.Listening or HostRunState.RelayConnected))throw new TetherException(TetherError.Unavailable);var value=await Request("pair-code",null,token);var code=value.GetProperty("code").GetString();var seconds=value.GetProperty("expires_in_seconds").GetInt32();var attempts=value.GetProperty("attempts_remaining").GetInt32();if(code is not{Length:8}||!code.All(c=>"0123456789ABCDEFGHJKMNPQRSTVWXYZ".Contains(c))||seconds is<1 or>300||attempts is<1 or>3)throw new TetherException(TetherError.Protocol);var window=new PairingWindow(code,DateTimeOffset.UtcNow.AddSeconds(seconds),attempts);lock(ownerState){EnsureOpen();if(State is not(HostRunState.Listening or HostRunState.RelayConnected))throw new TetherException(TetherError.Unavailable);Pairing=window;}Changed();return window;}finally{mutation.Release();}}
    public async Task RefreshPairingStatusAsync(CancellationToken token=default)
    {var value=await Request("pairing-status",null,token);if(value.GetProperty("open").ValueKind!=JsonValueKind.True||Pairing?.ExpiresAt<=DateTimeOffset.UtcNow)Pairing=null;Changed();}
    public async Task RefreshClientsAsync(CancellationToken token=default)
    {
        EnsureOpen();JsonElement root;if(Running)root=await Request("clients",null,token);else{var bytes=await Execute(Scoped("list"),token);try{using var doc=JsonDocument.Parse(bytes);root=doc.RootElement.Clone();}finally{CryptographicOperations.ZeroMemory(bytes);}}
        if(root.ValueKind!=JsonValueKind.Array||root.GetArrayLength()>256)throw new TetherException(TetherError.Protocol);var clients=new List<HostClient>();
        foreach(var entry in root.EnumerateArray()){var id=entry.GetProperty("device").GetString();if(id is not{Length:64}||!id.All(char.IsAsciiHexDigit)||clients.Any(c=>c.Id==id))throw new TetherException(TetherError.Protocol);var services=entry.GetProperty("services").EnumerateArray().Select(s=>s.GetString()??throw new TetherException(TetherError.Protocol)).ToArray();if(services.Length>32)throw new TetherException(TetherError.Protocol);foreach(var service in services)Scope.Validate(service);
            int? active=entry.TryGetProperty("active_sessions",out var a)?a.GetInt32():null;bool? recent=entry.TryGetProperty("recently_seen",out var b)?b.GetBoolean():null;long? seen=entry.TryGetProperty("last_seen_unix_ms",out var c)&&c.ValueKind!=JsonValueKind.Null?c.GetInt64():null;if(active is<0 or>24)throw new TetherException(TetherError.Protocol);clients.Add(new(id,services,active,recent,seen));}
        lock(ownerState){if(State is not(HostRunState.Listening or HostRunState.RelayConnected))clients=clients.Select(c=>c with{ActiveSessions=null,RecentlySeen=null,LastSeenUnixMs=null}).ToList();Clients=clients;}Changed();
    }
    public async Task RevokeAsync(string clientId,CancellationToken token=default)
    {if(clientId.Length!=64||!clientId.All(char.IsAsciiHexDigit))throw new TetherException(TetherError.InvalidScope);if(!await mutation.WaitAsync(0,token))throw new TetherException(TetherError.Busy);try{EnsureOpen();if(Running)_=await Request("revoke",clientId,token);else{var args=Scoped("revoke").Concat(new[]{"--device",clientId});using var p=new Process{StartInfo=StartInfo(args)};if(!p.Start())throw new TetherException(TetherError.Unavailable);using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,controllerLifetime.Token);using var d=Deadline.Start(linked.Token);var a=Drain(p.StandardOutput.BaseStream,d.Token);var b=Drain(p.StandardError.BaseStream,d.Token);try{await p.WaitForExitAsync(d.Token).ConfigureAwait(false);await Task.WhenAll(a,b);if(p.ExitCode!=0)throw new TetherException(TetherError.Unavailable);}finally{if(!p.HasExited)p.Kill(entireProcessTree:true);}}await RefreshClientsAsync(CancellationToken.None);}finally{mutation.Release();}}
    public async Task StopAsync(){if(!await mutation.WaitAsync(0))throw new TetherException(TetherError.Busy);try{await StopCore();}finally{mutation.Release();}}
    private async Task StopCore()
    {
        Task<bool> retiring;lock(ownerState){Pairing=null;ListeningAddress=null;ClearPresence();if(process is{} p){if(retirement.IsCompleted){var current=++epoch;lifetime?.Cancel();State=HostRunState.Stopping;retirement=RetireProcess(p,current,false);}retiring=retirement;}else{State=HostRunState.Stopped;retiring=Task.FromResult(true);}}
        foreach(var item in requests.ToArray())if(requests.TryRemove(item.Key,out var waiter))waiter.Completion.TrySetException(new TetherException(TetherError.Closed));Changed();
        if(!await retiring.ConfigureAwait(false))throw new TetherException(TetherError.Unavailable);
        lock(ownerState){if(process==null)State=HostRunState.Stopped;}Changed();
    }
    private async Task<bool> RetireProcess(Process p,long current,bool failed)
    {
        var exited=false;try{try{p.StandardInput.Close();}catch{}using var grace=new CancellationTokenSource(TimeSpan.FromSeconds(3));try{await p.WaitForExitAsync(grace.Token).ConfigureAwait(false);}catch(OperationCanceledException){TryKill(p);using var killed=new CancellationTokenSource(TimeSpan.FromSeconds(5));await p.WaitForExitAsync(killed.Token).ConfigureAwait(false);}exited=p.HasExited;}catch{}
        lock(ownerState){if(ReferenceEquals(process,p)&&current==epoch){if(exited){process=null;lifetime?.Cancel();lifetime?.Dispose();lifetime=null;}Pairing=null;ListeningAddress=null;ClearPresence();State=exited&&!failed?HostRunState.Stopped:HostRunState.Failed;}}
        if(exited)p.Dispose();Changed();return exited;
    }
    public async ValueTask DisposeAsync(){if(Interlocked.Exchange(ref closed,1)!=0)return;controllerLifetime.Cancel();await mutation.WaitAsync().ConfigureAwait(false);try{await StopCore().ConfigureAwait(false);}finally{mutation.Release();controllerLifetime.Dispose();}}
    private static async Task Drain(Stream stream,CancellationToken token){var bytes=new byte[4096];try{while(await stream.ReadAsync(bytes,token)>0)CryptographicOperations.ZeroMemory(bytes);}catch(OperationCanceledException){}catch(IOException){}catch(ObjectDisposedException){}finally{CryptographicOperations.ZeroMemory(bytes);}}
    private sealed class Lines(Stream stream,int limit)
    {
        private readonly byte[] buffer=new byte[4096];private int offset,count;
        internal async Task<byte[]?> Read(CancellationToken token){using var memory=new MemoryStream();while(true){if(offset==count){count=await stream.ReadAsync(buffer,token);offset=0;if(count==0){if(memory.Length!=0)throw new TetherException(TetherError.Protocol);return null;}}var value=buffer[offset++];if(value==10)return memory.ToArray();if(memory.Length>=limit)throw new TetherException(TetherError.Protocol);memory.WriteByte(value);}}
    }
}
