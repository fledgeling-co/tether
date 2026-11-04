using System.Runtime.InteropServices;
using System.Text.Json;

// Process-lifecycle fixture only. It opens no network listener, grants no peer and handles no secret.
if(args.Length<2||args[0]!="host")return 2;
if(args[1]=="inspect"){Console.WriteLine(JsonSerializer.Serialize(new{app_id="test.retirement",host_id=new string('a',52),services=Array.Empty<object>()}));return 0;}
if(args[1]!="run")return 2;
Console.WriteLine("{\"event\":\"listening\",\"address\":\"127.0.0.1:12345\"}");Console.Out.Flush();
var input=Console.ReadLine();if(input==null)return 2;using(var request=JsonDocument.Parse(input)){Console.WriteLine(JsonSerializer.Serialize(new{ @event="reply",request_id=request.RootElement.GetProperty("request_id").GetString(),ok=true,payload=Array.Empty<object>()}));Console.Out.Flush();}
Thread.Sleep(100);CloseHandle(GetStdHandle(-11));Thread.Sleep(1200);return 0;

[DllImport("kernel32.dll")]static extern IntPtr GetStdHandle(int which);
[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
