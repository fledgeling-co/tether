using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Tether.WinUI;

namespace Tether.Sample.WinUI;
public partial class App : Application
{
    private Window? window;private TetherClient? client;private TetherConnectionStore? connections;private TetherHostController? host;
    public App(){InitializeComponent();}
    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        window=new Window{Title="Tether — Windows framework sample"};
        try {
            var arguments=Environment.GetCommandLineArgs();string? root=null;string? verify=null;var appId="app.fledgeling.tether.sample";
            for(int i=1;i<arguments.Length;i++){if(arguments[i]=="--profile-root"&&i+1<arguments.Length)root=Path.GetFullPath(arguments[++i]);else if(arguments[i]=="--verify-output"&&i+1<arguments.Length)verify=Path.GetFullPath(arguments[++i]);else if(arguments[i]=="--app"&&i+1<arguments.Length)appId=arguments[++i];else throw new TetherException(TetherError.InvalidScope);}
            if(verify!=null){if(root==null||Directory.Exists(root)||!Path.GetFileName(root).StartsWith("tether-ui-",StringComparison.Ordinal)||!root.StartsWith(Path.GetFullPath(Path.GetTempPath()),StringComparison.OrdinalIgnoreCase))throw new TetherException(TetherError.InvalidScope);Directory.CreateDirectory(verify);foreach(var name in new[]{"hosts-wide","clients-wide","clients-narrow","clients-narrow-actions","hosts-narrow","hosts-narrow-actions","hosts-offline","hosts-revoked"}){await File.WriteAllBytesAsync(Path.Combine(verify,name+".png"),Array.Empty<byte>());await File.WriteAllBytesAsync(Path.Combine(verify,name+"-window.png"),Array.Empty<byte>());}await Verification.Run(window,root,verify);window.Close();Exit();return;}
            client=new(appId,new TetherProtectedStore(appId,root==null?null:Path.Combine(root,"client")));connections=new(client);
            host=new(appId,root==null?null:Path.Combine(root,"host","host.dpapi"));window.Content=new TetherWorkspaceView(connections,host);
            window.Closed+=async(_,_)=>{if(connections!=null)await connections.DisposeAsync();if(host!=null)await host.DisposeAsync();client?.Dispose();};
        }catch(Exception error){if(Environment.GetCommandLineArgs().Contains("--verify-output")){var arguments=Environment.GetCommandLineArgs();var index=Array.IndexOf(arguments,"--verify-output");if(index>=0&&index+1<arguments.Length)await File.WriteAllTextAsync(Path.Combine(Path.GetFullPath(arguments[index+1]),"failure.json"),System.Text.Json.JsonSerializer.Serialize(new{error=error.GetType().Name,message=error is TetherException t?t.Code.ToString():error.Message,stack=error.StackTrace}));Exit();return;}window.Content=new TextBlock{Text="The Tether framework could not open its protected profile or packaged helper.",Margin=new Thickness(24),TextWrapping=TextWrapping.Wrap};}
        window.Activate();
    }
}
