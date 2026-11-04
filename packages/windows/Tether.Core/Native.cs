using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Tether;

internal static class Native
{
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport("tether_ffi", CallingConvention=CallingConvention.Cdecl, EntryPoint="tether_call")]
    private static extern IntPtr CallNative(byte[] request, nuint length);
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]
    [DllImport("tether_ffi", CallingConvention=CallingConvention.Cdecl, EntryPoint="tether_free")]
    private static extern void FreeNative(IntPtr response);
    internal static NativeResponse Call(Dictionary<string, object?> request)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(request); IntPtr response=IntPtr.Zero; byte[]? output=null;
        try {
            if(bytes.Length is 0 or >131072) throw new TetherException(TetherError.Protocol);
            response=CallNative(bytes,(nuint)bytes.Length); if(response==IntPtr.Zero) throw new TetherException(TetherError.Protocol);
            int size=0; while(size<=131072 && Marshal.ReadByte(response,size)!=0) size++;
            if(size>131072) throw new TetherException(TetherError.Protocol);
            output=new byte[size]; Marshal.Copy(response,output,0,size);
            var document=new NativeResponse(output);output=null;
            if(!document.RootElement.TryGetProperty("ok",out var ok) || ok.ValueKind!=JsonValueKind.True) {
                var authentication=document.RootElement.TryGetProperty("error",out var e) && e.ValueKind==JsonValueKind.String && e.GetString()=="authentication_refused";
                document.Dispose(); throw new TetherException(authentication?TetherError.Authentication:TetherError.Protocol);
            }
            return document;
        } catch(DllNotFoundException) { throw new TetherException(TetherError.Unavailable); }
          catch(EntryPointNotFoundException) { throw new TetherException(TetherError.Unavailable); }
          catch(BadImageFormatException) { throw new TetherException(TetherError.Unavailable); }
          catch(JsonException) { throw new TetherException(TetherError.Protocol); }
        finally { CryptographicOperations.ZeroMemory(bytes); if(output!=null) CryptographicOperations.ZeroMemory(output); if(response!=IntPtr.Zero) FreeNative(response); }
    }
    internal static byte[] Data(JsonElement root,string name="data",int? size=null) {
        try { var b=root.GetProperty(name).GetBytesFromBase64(); if(size.HasValue && b.Length!=size) throw new FormatException(); return b; }
        catch { throw new TetherException(TetherError.Protocol); }
    }
    internal static ulong Handle(JsonElement root) { if(!root.TryGetProperty("handle",out var h)||!h.TryGetUInt64(out var n)||n==0) throw new TetherException(TetherError.Protocol); return n; }
    internal static void Destroy(ulong handle) { if(handle==0)return; try { using var _=Call(new(){{"command","destroy"},{"handle",handle}}); } catch { } }
}
internal sealed class NativeHandle : IDisposable
{
    private long value;
    internal NativeHandle(ulong handle) {value=checked((long)handle);}
    internal ulong Value => Interlocked.Read(ref value) is var n && n>0 ? (ulong)n : throw new TetherException(TetherError.Closed);
    internal ulong Take() { var n=Interlocked.Exchange(ref value,0); return n>0?(ulong)n:throw new TetherException(TetherError.Closed); }
    public void Dispose() { Native.Destroy((ulong)Interlocked.Exchange(ref value,0)); GC.SuppressFinalize(this); }
    ~NativeHandle() { Native.Destroy((ulong)Interlocked.Exchange(ref value,0)); }
}
internal sealed class Identity : IDisposable
{
    internal NativeHandle Handle {get;}
    internal byte[] Public {get;}
    internal Identity(NativeResponse response) { var id=Native.Handle(response.RootElement); try {Public=Native.Data(response.RootElement,"public",32);Handle=new(id);}catch{Native.Destroy(id);throw;} }
    public void Dispose()=>Handle.Dispose();
}

internal sealed class NativeResponse : IDisposable
{
    private readonly byte[] bytes;private JsonDocument? document;
    internal JsonElement RootElement=>document?.RootElement??throw new TetherException(TetherError.Closed);
    internal NativeResponse(byte[] ownedBytes){bytes=ownedBytes;document=JsonDocument.Parse((ReadOnlyMemory<byte>)bytes);}
    public void Dispose(){document?.Dispose();document=null;CryptographicOperations.ZeroMemory(bytes);GC.SuppressFinalize(this);}
    ~NativeResponse(){document?.Dispose();CryptographicOperations.ZeroMemory(bytes);}
}
