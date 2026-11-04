using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Automation;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text.Json;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Tether.WinUI;

namespace Tether.Sample.WinUI;

/// <summary>Explicit scratch-only native rendering witness. No installed profile or desktop capture is read.</summary>
internal static class Verification
{
    [DllImport("user32.dll")]private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]private static extern uint GetWindowThreadProcessId(IntPtr window,out uint process);
    private static uint Foreground(){GetWindowThreadProcessId(GetForegroundWindow(),out var id);return id;}
    internal static async Task Run(Window window,string root,string output)
    {
        var before=Foreground();var observations=new List<object>();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(40));var token=timeout.Token;
        var udp=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));using var lifetime=new CancellationTokenSource();var echo=Task.Run(async()=>{try{while(true){var packet=await udp.ReceiveAsync(lifetime.Token);await udp.SendAsync(packet.Buffer,packet.RemoteEndPoint,lifetime.Token);}}catch(OperationCanceledException){}catch(ObjectDisposedException){}});
        using var client=new TetherClient("test.windows.ui",new("test.windows.ui",Path.Combine(root,"client")));await using var store=new TetherConnectionStore(client,new(Array.Empty<TimeSpan>(),TimeSpan.FromMinutes(5)));await using var host=new TetherHostController("test.windows.ui",Path.Combine(root,"host","host.dpapi"));
        try {
            await host.InitializeAsync(new[]{new HostServiceProfile("audio",ServiceKind.Udp,"127.0.0.1",(ushort)((IPEndPoint)udp.Client.LocalEndPoint!).Port)},token);
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=(ushort)((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();await host.StartAsync(HostRoute.Direct("127.0.0.1",port),token);
            var pairing=await host.OpenPairingWindowAsync(token);var peer=await client.PairAsync(TetherRoute.Direct("127.0.0.1",port),pairing.Code,token);await host.RefreshPairingStatusAsync(token);if(host.Pairing!=null)throw new InvalidOperationException("Pairing code still present");await store.LoadAsync(token);await store.ConnectAsync(peer.Id,token);await using var channel=await store.OpenServiceAsync(peer.Id,"audio",ServiceKind.Udp,token);await channel.SendAsync(new byte[]{1,2,3},token);if(!(await channel.ReceiveAsync(token))!.SequenceEqual(new byte[]{1,2,3}))throw new InvalidOperationException("Fixture roundtrip failed");await host.RefreshClientsAsync(token);
            var view=new TetherWorkspaceView(store,host){Background=(Brush)Application.Current.Resources["ApplicationPageBackgroundThemeBrush"]};window.Content=view;window.AppWindow.Resize(new Windows.Graphics.SizeInt32(1500,1000));window.AppWindow.Show(false);
            await Task.Delay(600,token);
            var hostList=Find<ListView>(view).Single(list=>AutomationProperties.GetAutomationId(list)=="tether.hosts");var hostRow=(ListViewItem)hostList.Items[0];await store.DisconnectAsync(peer.Id);await store.ConnectAsync(peer.Id,token);await Task.Delay(100,token);if(!ReferenceEquals(hostRow,hostList.Items[0])||!ReferenceEquals(hostRow,hostList.SelectedItem))throw new InvalidOperationException("Host row native identity or selection changed during status refresh");
            await Capture(window,view,output,"hosts-wide",observations);var tabs=Find<TabView>(view).Single();tabs.SelectedIndex=1;await Task.Delay(500,token);var clientList=Find<ListView>(view).Single(list=>AutomationProperties.GetAutomationId(list)=="tether.clients");var clientRow=(ListViewItem)clientList.Items[0];clientList.SelectedItem=clientRow;await host.RefreshClientsAsync(token);await Task.Delay(100,token);if(!ReferenceEquals(clientRow,clientList.Items[0])||!ReferenceEquals(clientRow,clientList.SelectedItem))throw new InvalidOperationException("Client row native identity or selection changed during owner refresh");await Capture(window,view,output,"clients-wide",observations);
            window.AppWindow.Resize(new Windows.Graphics.SizeInt32(520,820));await Task.Delay(300,token);await Capture(window,view,output,"clients-narrow",observations);await ScrollAndCapture(window,view,output,"clients-narrow-actions",observations,token);tabs.SelectedIndex=0;await Task.Delay(250,token);await Capture(window,view,output,"hosts-narrow",observations);await ScrollAndCapture(window,view,output,"hosts-narrow-actions",observations,token);
            await store.DisconnectAsync(peer.Id);await Task.Delay(1200,token);await Capture(window,view,output,"hosts-offline",observations);
            await store.ReconnectAsync(peer.Id,token);await host.RefreshClientsAsync(token);await host.RevokeAsync(host.Clients.Single().Id,token);await store.ReconnectAsync(peer.Id,token);await Task.Delay(1200,token);await Capture(window,view,output,"hosts-revoked",observations);
            var after=Foreground();await File.WriteAllTextAsync(Path.Combine(output,"native-ui.json"),JsonSerializer.Serialize(new{schema="tether.windows-native-ui/1",runtime=Environment.Version.ToString(),foregroundBefore=before,foregroundAfter=after,foregroundPreserved=before==after,rowIdentityRefreshChecks=2,device="Z13",scope="Scratch native WinUI content plus own-window PrintWindow captures; no foreign window capture or physical/internet acceptance. RenderTargetBitmap omits some composition-backed control fills; use *-window.png for visual review.",observations},new JsonSerializerOptions{WriteIndented=true}),token);
        }finally{lifetime.Cancel();udp.Dispose();await echo;}
    }
    [StructLayout(LayoutKind.Sequential)]private struct Rect {public int Left,Top,Right,Bottom;}
    [StructLayout(LayoutKind.Sequential)]private struct BitmapHeader {public uint Size;public int Width,Height;public ushort Planes,BitCount;public uint Compression,SizeImage;public int XPelsPerMeter,YPelsPerMeter;public uint ColorsUsed,ColorsImportant;}
    [DllImport("user32.dll")]private static extern bool GetWindowRect(IntPtr window,out Rect rect);
    [DllImport("user32.dll")]private static extern IntPtr GetDC(IntPtr window);
    [DllImport("user32.dll")]private static extern int ReleaseDC(IntPtr window,IntPtr dc);
    [DllImport("gdi32.dll")]private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")]private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll")]private static extern IntPtr SelectObject(IntPtr dc,IntPtr item);
    [DllImport("gdi32.dll")]private static extern bool DeleteObject(IntPtr item);
    [DllImport("gdi32.dll")]private static extern IntPtr CreateDIBSection(IntPtr dc,ref BitmapHeader info,uint colors,out IntPtr bits,IntPtr section,uint offset);
    [DllImport("user32.dll")]private static extern bool PrintWindow(IntPtr window,IntPtr dc,uint flags);
    private static async Task CaptureWindow(Window window,string output,string name)
    {
        var handle=WinRT.Interop.WindowNative.GetWindowHandle(window);if(!GetWindowRect(handle,out var rect))throw new InvalidOperationException("Own window bounds unavailable");var width=rect.Right-rect.Left;var height=rect.Bottom-rect.Top;if(width is<1 or>4096||height is<1 or>4096)throw new InvalidOperationException("Own capture bounds invalid");
        var dc=GetDC(handle);var memory=CreateCompatibleDC(dc);var header=new BitmapHeader{Size=(uint)Marshal.SizeOf<BitmapHeader>(),Width=width,Height=-height,Planes=1,BitCount=32};var bitmap=CreateDIBSection(dc,ref header,0,out var bits,IntPtr.Zero,0);var old=SelectObject(memory,bitmap);
        try{if(!PrintWindow(handle,memory,2))throw new InvalidOperationException("Own PrintWindow failed");var pixels=new byte[checked(width*height*4)];Marshal.Copy(bits,pixels,0,pixels.Length);for(int i=3;i<pixels.Length;i+=4)pixels[i]=255;var file=await StorageFile.GetFileFromPathAsync(Path.Combine(output,name+"-window.png"));using var stream=await file.OpenAsync(FileAccessMode.ReadWrite);var encoder=await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId,stream);encoder.SetPixelData(BitmapPixelFormat.Bgra8,BitmapAlphaMode.Ignore,(uint)width,(uint)height,96,96,pixels);await encoder.FlushAsync();}
        finally{SelectObject(memory,old);DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(handle,dc);}
    }
    private static IEnumerable<T> Find<T>(DependencyObject root) where T:DependencyObject {if(root is T item)yield return item;for(int i=0;i<VisualTreeHelper.GetChildrenCount(root);i++)foreach(var nested in Find<T>(VisualTreeHelper.GetChild(root,i)))yield return nested;}
    private static async Task ScrollAndCapture(Window window,FrameworkElement view,string output,string name,List<object> observations,CancellationToken token)
    {var scroll=Find<ScrollViewer>(view).FirstOrDefault(s=>s.Content is Grid&&s.ScrollableHeight>0);if(scroll==null)throw new InvalidOperationException("Expected narrow overflow");scroll.ChangeView(null,scroll.ScrollableHeight,null,true);await Task.Delay(120,token);await Capture(window,view,output,name,observations);scroll.ChangeView(null,0,null,true);await Task.Delay(120,token);}
    private static async Task Capture(Window window,FrameworkElement view,string output,string name,List<object> observations)
    {
        view.UpdateLayout();var bitmap=new RenderTargetBitmap();await bitmap.RenderAsync(view);var pixels=await bitmap.GetPixelsAsync();var file=await StorageFile.GetFileFromPathAsync(Path.Combine(output,name+".png"));using var stream=await file.OpenAsync(FileAccessMode.ReadWrite);var encoder=await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId,stream);encoder.SetPixelData(BitmapPixelFormat.Bgra8,BitmapAlphaMode.Premultiplied,(uint)bitmap.PixelWidth,(uint)bitmap.PixelHeight,96,96,pixels.ToArray());await encoder.FlushAsync();
        await CaptureWindow(window,output,name);
        var scrolls=Find<ScrollViewer>(view).Where(s=>s.Visibility==Visibility.Visible&&s.ActualWidth>0).Select(s=>new{width=s.ActualWidth,horizontal=s.ScrollableWidth,vertical=s.ScrollableHeight}).ToArray();
        observations.Add(new{frame=name,width=bitmap.PixelWidth,height=bitmap.PixelHeight,text=Find<TextBlock>(view).Where(t=>t.Visibility==Visibility.Visible).Select(t=>t.Text).Where(t=>!string.IsNullOrEmpty(t)).Distinct().ToArray(),controls=Find<FrameworkElement>(view).Select(AutomationProperties.GetAutomationId).Where(id=>!string.IsNullOrEmpty(id)).Distinct().ToArray(),scrolls});
        if(scrolls.Any(s=>s.horizontal>1))throw new InvalidOperationException("Horizontal scrolling in native framework");
    }
}
