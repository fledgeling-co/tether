using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Tether;

namespace Tether.WinUI;

internal static class Controls
{
    internal static TextBlock Text(string text,bool heading=false){var block=new TextBlock{Text=text,TextWrapping=TextWrapping.Wrap};if(heading&&Application.Current.Resources.TryGetValue("SubtitleTextBlockStyle",out var style))block.Style=(Style)style;return block;}
    internal static Button Button(string title,string id,RoutedEventHandler action){var button=new Button{Content=new TextBlock{Text=title,TextWrapping=TextWrapping.Wrap,TextAlignment=TextAlignment.Center}};AutomationProperties.SetName(button,title);AutomationProperties.SetAutomationId(button,id);button.Click+=action;return button;}
    internal static TextBox Field(string title,string id,string value=""){var field=new TextBox{Header=title,Text=value};AutomationProperties.SetAutomationId(field,id);return field;}
    internal static StackPanel Stack(params UIElement[] children){var stack=new StackPanel{Spacing=12};foreach(var child in children)stack.Children.Add(child);return stack;}
    internal static Grid Actions(params Button[] buttons)
    {var grid=new Grid{ColumnSpacing=8,RowSpacing=8};grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});grid.ColumnDefinitions.Add(new(){Width=new GridLength(1,GridUnitType.Star)});for(int i=0;i<buttons.Length;i++){if(i%2==0)grid.RowDefinitions.Add(new(){Height=GridLength.Auto});Grid.SetColumn(buttons[i],i%2);Grid.SetRow(buttons[i],i/2);buttons[i].HorizontalAlignment=HorizontalAlignment.Stretch;grid.Children.Add(buttons[i]);}return grid;}
    internal static Expander Form(string title,UIElement body,string id){var form=new Expander{Header=title,Content=body,HorizontalAlignment=HorizontalAlignment.Stretch,HorizontalContentAlignment=HorizontalAlignment.Stretch};AutomationProperties.SetAutomationId(form,id);return form;}
    internal static ScrollViewer Columns(FrameworkElement sidebar,FrameworkElement detail)
    {
        var grid=new Grid{ColumnSpacing=24,RowSpacing=24};grid.ColumnDefinitions.Add(new());grid.ColumnDefinitions.Add(new());grid.RowDefinitions.Add(new());grid.RowDefinitions.Add(new());grid.Children.Add(sidebar);grid.Children.Add(detail);
        grid.SizeChanged+=(_,e)=>{var wide=e.NewSize.Width>=760;grid.ColumnDefinitions[0].Width=wide?new GridLength(256):new GridLength(1,GridUnitType.Star);grid.ColumnDefinitions[1].Width=wide?new GridLength(1,GridUnitType.Star):new GridLength(0);grid.RowDefinitions[0].Height=GridLength.Auto;grid.RowDefinitions[1].Height=GridLength.Auto;Grid.SetColumn(detail,wide?1:0);Grid.SetRow(detail,wide?0:1);};
        return new ScrollViewer{Content=grid,Padding=new Thickness(20),HorizontalScrollMode=ScrollMode.Disabled,HorizontalScrollBarVisibility=ScrollBarVisibility.Disabled,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
    }
    internal static void UpdateRows(ListView list,IEnumerable<(string Id,string First,string Second)> rows,string? selected,string idPrefix)
    {
        var values=rows.ToArray();var valid=values.Select(value=>value.Id).ToHashSet(StringComparer.Ordinal);
        for(int i=list.Items.Count-1;i>=0;i--)if(list.Items[i] is not ListViewItem item||item.Tag is not string id||!valid.Contains(id))list.Items.RemoveAt(i);
        for(int i=0;i<values.Length;i++)
        {
            var value=values[i];var row=list.Items.OfType<ListViewItem>().FirstOrDefault(item=>Equals(item.Tag,value.Id));
            if(row==null){row=new(){MinHeight=72,Padding=new Thickness(8),HorizontalContentAlignment=HorizontalAlignment.Stretch,Tag=value.Id,Content=Stack(Text(value.First),Text(value.Second))};AutomationProperties.SetAutomationId(row,idPrefix+value.Id);list.Items.Insert(i,row);}
            else if(list.Items.IndexOf(row)!=i){list.Items.Remove(row);list.Items.Insert(i,row);}
            var labels=((StackPanel)row.Content).Children.OfType<TextBlock>().ToArray();if(labels[0].Text!=value.First)labels[0].Text=value.First;if(labels[1].Text!=value.Second)labels[1].Text=value.Second;
            var name=value.First+". "+value.Second;if(AutomationProperties.GetName(row)!=name)AutomationProperties.SetName(row,name);
        }
        var selectedRow=list.Items.OfType<ListViewItem>().FirstOrDefault(item=>Equals(item.Tag,selected));if(!ReferenceEquals(list.SelectedItem,selectedRow))list.SelectedItem=selectedRow;
    }
    internal static string Fingerprint(string key)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Convert.FromBase64String(key))).ToLowerInvariant()[..16];
    internal static string State(ConnectionState state)=>state switch{ConnectionState.IdentityMismatch=>"Identity changed",ConnectionState.Revoked=>"Permission revoked",ConnectionState.Capacity=>"Host at capacity",_=>state.ToString()};
    internal static async Task<bool> Confirm(FrameworkElement owner,string title,string consequence)
    {var dialog=new ContentDialog{XamlRoot=owner.XamlRoot,Title=title,Content=consequence,PrimaryButtonText="Confirm",CloseButtonText="Cancel",DefaultButton=ContentDialogButton.Close};return await dialog.ShowAsync()==ContentDialogResult.Primary;}
}

/// <summary>Embeddable saved-host management. Pairing, status and route changes use the supplied real client controller.</summary>
public sealed class TetherClientView : UserControl
{
    private readonly TetherConnectionStore store;private readonly ListView hosts=new(){MaxHeight=220};private readonly TextBlock selected=Controls.Text("Select a host",true),services=Controls.Text("No granted services received.");
    private readonly InfoBar status=new(){IsOpen=true,IsClosable=false};private readonly TextBlock error=Controls.Text("");
    private readonly ComboBox routeMode=new(){Header="Connection route",ItemsSource=new[]{"Private network or VPN","Cloud relay"},SelectedIndex=0};
    private readonly TextBox address=Controls.Field("Host address","tether.route.address","127.0.0.1"),port=Controls.Field("Port","tether.route.port","7445"),relay=Controls.Field("Relay URL (wss)","tether.route.relay"),hostId=Controls.Field("Cloud host ID","tether.route.hostId");
    private readonly PasswordBox code=new(){Header="Pairing code"};private readonly Button connect,disconnect,leave,forget,recover,discard,saveRoute,pair,cancel;
    private bool rendering,busy;private CancellationTokenSource? operation;
    public TetherClientView(TetherConnectionStore store)
    {
        this.store=store;AutomationProperties.SetAutomationId(hosts,"tether.hosts");AutomationProperties.SetName(hosts,"Saved hosts");AutomationProperties.SetName(routeMode,"Connection route");AutomationProperties.SetAutomationId(code,"tether.pair.code");
        connect=Controls.Button("Connect","tether.connect",async(_,_)=>await Run(t=>store.ReconnectAsync(Id(),t)));
        disconnect=Controls.Button("Disconnect","tether.disconnect",async(_,_)=>{operation?.Cancel();try{await store.DisconnectAsync(Id());}catch{error.Text="Could not disconnect this host.";}Refresh();});
        leave=Controls.Button("Leave host…","tether.leave",async(_,_)=>{var id=Id();var record=store.Hosts.Single(h=>h.Id==id).Record;if(await Controls.Confirm(this,"Leave host "+Controls.Fingerprint(record.HostKey)+"?","Revoke this device at this host, then remove its saved local trust. Open streams to this host will close. If confirmation fails, saved trust stays available for retry."))await Run(t=>{RequireRecord(id,record);return store.LeaveAsync(id,t);});});
        forget=Controls.Button("Forget locally…","tether.forget",async(_,_)=>{var id=Id();var record=store.Hosts.Single(h=>h.Id==id).Record;if(await Controls.Confirm(this,"Forget host "+Controls.Fingerprint(record.HostKey)+" locally?","Remove this app's saved trust and close its streams. The host is not contacted and may still authorize this device."))await Run(t=>{RequireRecord(id,record);return store.ForgetLocallyAsync(id,t);});});
        recover=Controls.Button("Recover pairing","tether.recover",async(_,_)=>await Run(t=>store.RecoverAsync(Id(),t)));
        discard=Controls.Button("Discard pending…","tether.discard",async(_,_)=>{var id=Id();var record=store.Hosts.Single(h=>h.Id==id).Record;if(await Controls.Confirm(this,"Discard pending pairing?","Remove only this pending local record. This does not revoke permission at the host. A fresh owner pairing code will be needed."))await Run(t=>{RequireRecord(id,record);return store.DiscardPendingPairingAsync(id,t);});});
        saveRoute=Controls.Button("Change route…","tether.route.save",async(_,_)=>await EditRoute());
        pair=Controls.Button("Pair host","tether.pair",async(_,_)=>{var value=code.Password;code.Password="";await Run(async t=>{_=await store.PairAsync(Route(),value,t);});});
        cancel=Controls.Button("Cancel operation","tether.cancel",(_,_)=>operation?.Cancel());
        var pairing=Controls.Form("Pair another host",Controls.Stack(Controls.Text("Enter the host's explicit private-network, VPN or cloud route and its current owner pairing code."),routeMode,address,port,relay,hostId,code,pair),"tether.pair.form");
        Content=Controls.Columns(Controls.Stack(Controls.Text("Hosts",true),Controls.Text("Saved permission and live status are separate."),hosts,pairing),Controls.Stack(selected,status,Controls.Text("Authorized services",true),services,Controls.Actions(connect,disconnect,saveRoute,leave,forget,recover,discard),cancel,error));
        hosts.SelectionChanged+=(_,_)=>{if(rendering)return;if(hosts.SelectedItem is ListViewItem row&&row.Tag is string id){store.SelectedHostId=id;FillRoute();}Refresh();};routeMode.SelectionChanged+=(_,_)=>RefreshRoute();
        store.PropertyChanged+=OnChanged;Loaded+=async(_,_)=>await Run(t=>store.LoadAsync(t));Refresh();
    }
    private async Task EditRoute()
    {
        var id=Id();var record=store.Hosts.Single(h=>h.Id==id).Record;var old=record.Route;
        var mode=new ComboBox{Header="Route",ItemsSource=new[]{"Private network or VPN","Cloud relay"},SelectedIndex=old.Mode=="cloud"?1:0};
        var host=Controls.Field("Host address","tether.route.edit.address",old.Host??"");var number=Controls.Field("Port","tether.route.edit.port",old.Port.ToString());var url=Controls.Field("Relay URL (wss)","tether.route.edit.relay",old.Url??"");var cloudId=Controls.Field("Cloud host ID","tether.route.edit.hostId",old.HostId??"");
        void Update(){host.Visibility=number.Visibility=mode.SelectedIndex==1?Visibility.Collapsed:Visibility.Visible;url.Visibility=cloudId.Visibility=mode.SelectedIndex==1?Visibility.Visible:Visibility.Collapsed;}mode.SelectionChanged+=(_,_)=>Update();Update();
        var dialog=new ContentDialog{XamlRoot=XamlRoot,Title="Change route for "+Controls.Fingerprint(record.HostKey),PrimaryButtonText="Check and save",CloseButtonText="Cancel",DefaultButton=ContentDialogButton.Close,Content=Controls.Stack(Controls.Text("The same pinned host and client must authenticate before the saved route changes. Failure keeps the old route and its open streams."),mode,host,number,url,cloudId)};
        if(await dialog.ShowAsync()!=ContentDialogResult.Primary)return;
        await Run(t=>{RequireRecord(id,record);var value=mode.SelectedIndex==1?TetherRoute.Cloud(url.Text.Trim(),cloudId.Text.Trim()):ushort.TryParse(number.Text,out var port)&&port>0?TetherRoute.Direct(host.Text.Trim(),port):throw new TetherException(TetherError.InvalidRoute);return store.ChangeRouteAsync(id,value,t);});
    }
    private void OnChanged(object? sender,System.ComponentModel.PropertyChangedEventArgs e){if(DispatcherQueue.HasThreadAccess)Refresh();else DispatcherQueue.TryEnqueue(Refresh);}
    private void RequireRecord(string id,PeerRecord expected){if(store.Hosts.SingleOrDefault(h=>h.Id==id)?.Record!=expected)throw new TetherException(TetherError.IdentityMismatch);}
    private string Id()=>store.SelectedHostId??throw new TetherException(TetherError.InvalidScope);
    private TetherRoute Route(){if(routeMode.SelectedIndex==1)return TetherRoute.Cloud(relay.Text.Trim(),hostId.Text.Trim());if(!ushort.TryParse(port.Text,out var value)||value==0)throw new TetherException(TetherError.InvalidRoute);return TetherRoute.Direct(address.Text.Trim(),value);}
    private void FillRoute(){var route=store.Hosts.FirstOrDefault(h=>h.Id==store.SelectedHostId)?.Record.Route;if(route==null)return;routeMode.SelectedIndex=route.Mode=="cloud"?1:0;address.Text=route.Host??"";port.Text=route.Port.ToString();relay.Text=route.Url??"";hostId.Text=route.HostId??"";}
    private void RefreshRoute(){var cloud=routeMode.SelectedIndex==1;address.Visibility=port.Visibility=cloud?Visibility.Collapsed:Visibility.Visible;relay.Visibility=hostId.Visibility=cloud?Visibility.Visible:Visibility.Collapsed;}
    private void Refresh()
    {
        rendering=true;try{Controls.UpdateRows(hosts,store.Hosts.Select(host=>(host.Id,host.Record.Route.Mode=="direct"?host.Record.Route.Host??"Private host":"Cloud host",Controls.Fingerprint(host.Record.HostKey)+" · "+Controls.State(host.State))),store.SelectedHostId,"tether.host.");}
        finally{rendering=false;}
        var current=store.Hosts.FirstOrDefault(h=>h.Id==store.SelectedHostId);selected.Text=current==null?"Select a host":"Host key "+Controls.Fingerprint(current.Record.HostKey);status.Title=current==null?"No saved host":Controls.State(current.State);status.Message=current?.Notice??(current?.State==ConnectionState.Connected?"Authenticated status received "+current.LastChecked?.ToLocalTime().ToString("T")+".":"Saved trust does not establish that this host is online.");status.Severity=current?.State==ConnectionState.Connected?InfoBarSeverity.Success:current?.State is ConnectionState.IdentityMismatch or ConnectionState.Revoked?InfoBarSeverity.Error:InfoBarSeverity.Informational;
        services.Text=current?.Services.Count>0?"Granted services: "+string.Join(", ",current.Services.Select(s=>s.Id+" ("+s.Kind.ToString().ToLowerInvariant()+")")):current?.State==ConnectionState.Connected?"This host grants no services to this device.":"No current granted service list received.";
        var confirmed=current?.Record.Confirmed==true;connect.IsEnabled=!busy&&confirmed;disconnect.IsEnabled=current?.State is ConnectionState.Connected or ConnectionState.Connecting or ConnectionState.Reconnecting or ConnectionState.Capacity;leave.IsEnabled=forget.IsEnabled=saveRoute.IsEnabled=!busy&&confirmed;recover.IsEnabled=discard.IsEnabled=!busy&&current is{Record.Confirmed:false};pair.IsEnabled=!busy;cancel.Visibility=busy?Visibility.Visible:Visibility.Collapsed;recover.Visibility=discard.Visibility=current is{Record.Confirmed:false}?Visibility.Visible:Visibility.Collapsed;RefreshRoute();
    }
    private async Task Run(Func<CancellationToken,Task> action){if(busy)return;busy=true;error.Text="";operation=new();Refresh();try{await action(operation.Token);}catch(TetherException e){error.Text=e.Message;}catch(OperationCanceledException){error.Text="Operation cancelled.";}catch{error.Text="The operation could not complete. Check this host and retry.";}finally{operation.Dispose();operation=null;busy=false;Refresh();}}
}

/// <summary>Host-owner management. Saved client permission is never labelled as an online connection.</summary>
public sealed class TetherHostView : UserControl
{
    private readonly TetherHostController host;private readonly ListView clients=new(){MaxHeight=220};private readonly TextBlock state=Controls.Text("Stopped",true),identity=Controls.Text("No host profile read."),pairing=Controls.Text("No pairing window open."),error=Controls.Text("");
    private readonly TextBox serviceId=Controls.Field("Service ID","tether.host.serviceId","api"),target=Controls.Field("Fixed loopback target port","tether.host.targetPort","8882"),listen=Controls.Field("Listen address","tether.host.listenAddress","127.0.0.1"),port=Controls.Field("Listen port","tether.host.listenPort","7445"),relay=Controls.Field("Relay URL (wss)","tether.host.relay");
    private readonly ComboBox kind=new(){Header="Service transport",ItemsSource=new[]{"TCP","UDP"},SelectedIndex=0},route=new(){Header="Host route",ItemsSource=new[]{"Private network or VPN","Cloud relay"},SelectedIndex=0};
    private readonly StackPanel profileCreator;private readonly TextBlock profileSummary=Controls.Text("");private readonly Button initialize,start,stop,open,revoke;private readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(2)};private bool busy,ticking;private CancellationTokenSource? operation;
    public TetherHostView(TetherHostController host)
    {
        this.host=host;AutomationProperties.SetAutomationId(clients,"tether.clients");AutomationProperties.SetName(clients,"Authorized clients");AutomationProperties.SetName(route,"Host route");AutomationProperties.SetName(kind,"Service transport");
        initialize=Controls.Button("Create host profile","tether.host.initialize",async(_,_)=>await Run(t=>{if(!ushort.TryParse(target.Text,out var p)||p==0)throw new TetherException(TetherError.InvalidRoute);return host.InitializeAsync(new[]{new HostServiceProfile(serviceId.Text.Trim(),kind.SelectedIndex==0?ServiceKind.Tcp:ServiceKind.Udp,"127.0.0.1",p)},t);}));
        start=Controls.Button("Start host","tether.host.start",async(_,_)=>await Run(t=>{if(route.SelectedIndex==1)return host.StartAsync(HostRoute.Cloud(relay.Text.Trim()),t);if(!ushort.TryParse(port.Text,out var p)||p==0)throw new TetherException(TetherError.InvalidRoute);return host.StartAsync(HostRoute.Direct(listen.Text.Trim(),p),t);}));
        stop=Controls.Button("Stop host","tether.host.stop",async(_,_)=>{if(busy){operation?.Cancel();return;}await Run(_=>host.StopAsync());});
        open=Controls.Button("Open pairing window","tether.host.pair",async(_,_)=>await Run(async t=>{_=await host.OpenPairingWindowAsync(t);}));
        revoke=Controls.Button("Remove client…","tether.host.revoke",async(_,_)=>{if(clients.SelectedItem is ListViewItem row&&row.Tag is string id&&await Controls.Confirm(this,"Remove client "+id[..12]+"?","Revoke this client's permission for this application and close its authorized streams. It will need a new pairing code to return. Client ID: "+id))await Run(t=>host.RevokeAsync(id,t));});
        var refresh=Controls.Button("Read clients","tether.host.refresh",async(_,_)=>await Run(t=>host.RefreshClientsAsync(t)));
        profileCreator=Controls.Stack(serviceId,kind,target,initialize);var profile=Controls.Form("Host profile",Controls.Stack(Controls.Text("This app owns fixed loopback targets. Remote clients choose a granted service ID."),profileSummary,profileCreator),"tether.host.profile");
        var connection=Controls.Form("Listener route",Controls.Stack(route,listen,port,relay),"tether.host.route");
        Content=Controls.Columns(Controls.Stack(Controls.Text("Clients",true),Controls.Text("Active and recently seen are observations from this running host. Saved permission alone does not mean online."),clients,Controls.Actions(refresh,revoke)),Controls.Stack(Controls.Text("This host",true),identity,state,Controls.Actions(start,stop,open),pairing,connection,profile,error));
        host.PropertyChanged+=(_,_)=>{if(DispatcherQueue.HasThreadAccess)Refresh();else DispatcherQueue.TryEnqueue(Refresh);};clients.SelectionChanged+=(_,_)=>revoke.IsEnabled=!busy&&clients.SelectedItem!=null;route.SelectionChanged+=(_,_)=>RefreshRoute();
        timer.Tick+=async(_,_)=>{if(ticking||busy||host.State is not(HostRunState.Listening or HostRunState.RelayConnected))return;ticking=true;try{if(host.Pairing!=null)await host.RefreshPairingStatusAsync();await host.RefreshClientsAsync();}catch{error.Text="Could not refresh this host's observations.";}finally{ticking=false;Refresh();}};
        Loaded+=async(_,_)=>{timer.Start();if(File.Exists(host.ProfilePath))await Run(async t=>{await host.InspectAsync(t);await host.RefreshClientsAsync(t);});};Unloaded+=(_,_)=>timer.Stop();Refresh();
    }
    private void RefreshRoute(){var cloud=route.SelectedIndex==1;listen.Visibility=port.Visibility=cloud?Visibility.Collapsed:Visibility.Visible;relay.Visibility=cloud?Visibility.Visible:Visibility.Collapsed;}
    private void Refresh()
    {
        state.Text=host.State==HostRunState.Listening?"Listening at "+host.ListeningAddress:host.State.ToString();identity.Text=host.HostId==null?"Application: "+host.AppId:"Application: "+host.AppId+"\nCloud host ID: "+host.HostId;
        pairing.Text=host.Pairing is{} window&&window.ExpiresAt>DateTimeOffset.UtcNow?"Pairing code: "+window.Code+"\nExpires "+window.ExpiresAt.ToLocalTime().ToString("T")+". Attempts remaining: "+window.AttemptsRemaining:"No pairing code available.";
        var selected=(clients.SelectedItem as ListViewItem)?.Tag as string;var running=host.State is HostRunState.Listening or HostRunState.RelayConnected;
        Controls.UpdateRows(clients,host.Clients.Select(client=>{var presence=!running||client.ActiveSessions==null?"Presence unknown":client.ActiveSessions>0?"Active":client.RecentlySeen==true?"Seen recently":"Not connected";return(client.Id,client.Id[..16]+" · "+presence,"Granted: "+string.Join(", ",client.Services));}),selected,"tether.client.");
        var exists=File.Exists(host.ProfilePath);profileCreator.Visibility=exists?Visibility.Collapsed:Visibility.Visible;profileSummary.Text=!exists?"Create a profile before starting this host.":host.Services.Count==0?"No service configuration has been verified.":"Profile services: "+string.Join(", ",host.Services.Select(s=>s.Id+" ("+s.Kind.ToString().ToLowerInvariant()+")"))+". Targets are managed by this app’s profile.";initialize.IsEnabled=!busy&&!exists;start.IsEnabled=!busy&&host.State is HostRunState.Stopped or HostRunState.Failed;stop.IsEnabled=host.State!=HostRunState.Stopped;open.IsEnabled=!busy&&running;revoke.IsEnabled=!busy&&clients.SelectedItem!=null;serviceId.IsEnabled=kind.IsEnabled=target.IsEnabled=initialize.IsEnabled;RefreshRoute();
    }
    private async Task Run(Func<CancellationToken,Task> action){if(busy)return;busy=true;error.Text="";operation=new();Refresh();try{await action(operation.Token);}catch(TetherException e){error.Text=e.Message;}catch(OperationCanceledException){error.Text="Operation cancelled.";}catch{error.Text="The host operation could not complete. Read its current state before retrying.";}finally{operation.Dispose();operation=null;busy=false;Refresh();}}
}
public sealed class TetherWorkspaceView : UserControl
{
    public TetherWorkspaceView(TetherConnectionStore clients,TetherHostController host)
    {var tabs=new TabView{IsAddTabButtonVisible=false,CanDragTabs=false};tabs.TabItems.Add(new TabViewItem{Header="Hosts",IsClosable=false,Content=new TetherClientView(clients)});tabs.TabItems.Add(new TabViewItem{Header="Clients",IsClosable=false,Content=new TetherHostView(host)});Content=tabs;}
}
