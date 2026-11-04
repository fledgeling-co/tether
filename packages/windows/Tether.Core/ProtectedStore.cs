using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Tether;

/// <summary>App-scoped DPAPI CurrentUser records. Broad ACLs, reparse points and corruption refuse access.</summary>
public sealed class TetherProtectedStore
{
    public string AppId { get; }
    internal string DirectoryPath { get; }
    private readonly object gate=new();
    internal static readonly JsonSerializerOptions Json=new() { PropertyNamingPolicy=JsonNamingPolicy.CamelCase, UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow };
    public TetherProtectedStore(string appId,string? directory=null)
    {
        Scope.Validate(appId); AppId=appId;
        if(!OperatingSystem.IsWindows()) throw new TetherException(TetherError.Storage);
        DirectoryPath=Path.GetFullPath(directory??Scope.ProfileDirectory(appId));
        PrivateFiles.PrepareDirectory(DirectoryPath);
    }
    internal Identity Identity()
    {
        return Locked(()=>{
            var path=Path.Combine(DirectoryPath,"identity.dpapi");
            if(File.Exists(path)) {
                var key=Read(path,32);try { using var result=Native.Call(new(){{"command","identity.fromPrivate"},{"private",key}}); return new Identity(result); }
                finally{CryptographicOperations.ZeroMemory(key);}
            }
            using var generated=Native.Call(new(){{"command","identity.generate"}});
            var secret=Native.Data(generated.RootElement,"private",32);
            try { Save(path,secret,true); return new Identity(generated); }
            catch { Native.Destroy(Native.Handle(generated.RootElement)); throw; }
            finally {CryptographicOperations.ZeroMemory(secret);}
        });
    }
    public IReadOnlyList<PeerRecord> Records() => Locked(()=> {
        var paths=Directory.EnumerateFiles(DirectoryPath,"peer-*.dpapi").Take(257).ToArray(); if(paths.Length>256)throw new TetherException(TetherError.Storage);
        return (IReadOnlyList<PeerRecord>)paths.Select(ReadPeer).OrderBy(p=>p.Id,StringComparer.Ordinal).ToArray();
    });
    internal PeerRecord? Find(string hostKey) => Locked(()=>FindUnlocked(hostKey));
    private PeerRecord? FindUnlocked(string hostKey) { Scope.Key(hostKey); var path=PeerPath(hostKey);return File.Exists(path)?ReadPeer(path):null; }
    private string PeerPath(string key)=>Path.Combine(DirectoryPath,"peer-"+Scope.FileId(key)+".dpapi");
    private PeerRecord ReadPeer(string path)
    {
        var bytes=Read(path,8192);
        try {var peer=JsonSerializer.Deserialize<PeerRecord>(bytes,Json)??throw new TetherException(TetherError.Storage);peer.Validate(AppId);if(PeerPath(peer.HostKey)!=path)throw new TetherException(TetherError.Storage);return peer;}
        catch(TetherException){throw;}catch{throw new TetherException(TetherError.Storage);}finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal void Begin(PeerRecord peer) => Locked(()=>{peer.Validate(AppId);if(peer.Confirmed||FindUnlocked(peer.HostKey)!=null)throw new TetherException(TetherError.PairingExists);if(Directory.EnumerateFiles(DirectoryPath,"peer-*.dpapi").Take(256).Count()>=256)throw new TetherException(TetherError.Storage);SavePeer(peer,true);return true;});
    internal PeerRecord Confirm(PeerRecord expected) => Locked(()=>{
        var actual=FindUnlocked(expected.HostKey); if(actual==null||(actual with{Confirmed=expected.Confirmed})!=expected)throw new TetherException(TetherError.IdentityMismatch);
        if(actual.Confirmed)return actual;var confirmed=actual with{Confirmed=true};SavePeer(confirmed,false);return confirmed;
    });
    internal void ReplaceConfirmed(PeerRecord expected,PeerRecord replacement) => Locked(()=>{
        expected.Validate(AppId);replacement.Validate(AppId);
        if(!expected.Confirmed||!replacement.Confirmed||expected.HostKey!=replacement.HostKey||expected.ClientKey!=replacement.ClientKey||expected.PairingId==replacement.PairingId||FindUnlocked(expected.HostKey)!=expected)throw new TetherException(TetherError.IdentityMismatch);
        SavePeer(replacement,false);return true;
    });
    internal void Remove(PeerRecord expected,bool confirmed) => Locked(()=>{
        if(expected.Confirmed!=confirmed||FindUnlocked(expected.HostKey)!=expected)throw new TetherException(TetherError.IdentityMismatch);
        PrivateFiles.Validate(PeerPath(expected.HostKey),false);File.Delete(PeerPath(expected.HostKey));return true;
    });
    private void SavePeer(PeerRecord peer,bool createOnly) {var bytes=JsonSerializer.SerializeToUtf8Bytes(peer,Json);try{if(bytes.Length>8192)throw new TetherException(TetherError.Storage);Save(PeerPath(peer.HostKey),bytes,createOnly);}finally{CryptographicOperations.ZeroMemory(bytes);}}
    private T Locked<T>(Func<T> operation)
    {
        lock(gate) {
            try {
                PrivateFiles.Validate(DirectoryPath,true);
                using var file=PrivateFiles.OpenLock(Path.Combine(DirectoryPath,"store.lock"));
                for(int attempt=0;;attempt++){try{file.Lock(0,1);break;}catch(IOException){if(attempt>=49)throw;Thread.Sleep(20);}}
                try{return operation();}finally{file.Unlock(0,1);}
            } catch(TetherException){throw;}catch{throw new TetherException(TetherError.Storage);}
        }
    }
    private byte[] Read(string path,int limit)
    {
        using var stream=PrivateFiles.Read(path);if(stream.Length>limit+16384)throw new TetherException(TetherError.Storage);var bytes=new byte[checked((int)stream.Length)];stream.ReadExactly(bytes);
        var plain=Dpapi.Transform(bytes,AppId,decrypt:true);if(plain.Length>limit){CryptographicOperations.ZeroMemory(plain);throw new TetherException(TetherError.Storage);}return plain;
    }
    private void Save(string path,byte[] bytes,bool createOnly)
    {
        var encrypted=Dpapi.Transform(bytes,AppId,decrypt:false);var temporary=createOnly?path:path+"."+Guid.NewGuid().ToString("N")+".tmp";var created=false;var complete=false;
        try {
            using(var stream=PrivateFiles.Create(temporary)){created=true;stream.Write(encrypted);stream.Flush(true);}
            if(!createOnly){PrivateFiles.Validate(path,false);if(!PrivateFiles.MoveFileEx(temporary,path,1|8))throw new TetherException(TetherError.Storage);}complete=true;
        } finally {CryptographicOperations.ZeroMemory(encrypted);if(created&&(!createOnly||!complete)&&File.Exists(temporary))File.Delete(temporary);}
    }
}

internal static class PrivateFiles
{
    [StructLayout(LayoutKind.Sequential)]private struct SecurityAttributes {public int Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool CreateDirectoryW(string path,ref SecurityAttributes attributes);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFileW(string path,uint access,uint sharing,ref SecurityAttributes attributes,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]internal static extern bool MoveFileEx(string from,string to,uint flags);
    [DllImport("advapi32.dll",SetLastError=true)]private static extern uint GetSecurityInfo(SafeFileHandle handle,uint objectType,uint information,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")]private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]private static extern IntPtr LocalFree(IntPtr value);
    [StructLayout(LayoutKind.Sequential)]private struct AttributeTag {public uint Attributes;public uint ReparseTag;}
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle,int information,out AttributeTag attributes,uint size);
    private static SecurityIdentifier User { get { using var identity=WindowsIdentity.GetCurrent();return identity.User??throw new TetherException(TetherError.Storage); } }
    private static T WithSecurity<T>(Func<SecurityAttributes,T> operation)
    {
        var user=User;var descriptor=new RawSecurityDescriptor("O:"+user.Value+"D:P(A;;FA;;;"+user.Value+")");var bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
        var pin=GCHandle.Alloc(bytes,GCHandleType.Pinned);try{return operation(new SecurityAttributes{Length=Marshal.SizeOf<SecurityAttributes>(),Descriptor=pin.AddrOfPinnedObject(),Inherit=false});}finally{pin.Free();}
    }
    private static void NoReparse(string path)
    {
        path=Path.GetFullPath(path);if(path.StartsWith(@"\\",StringComparison.Ordinal)||Path.GetPathRoot(path)?.Length!=3)throw new TetherException(TetherError.Storage);
        for(var item=new DirectoryInfo(path);item!=null;item=item.Parent){if((Directory.Exists(item.FullName)||File.Exists(item.FullName))&&(File.GetAttributes(item.FullName)&FileAttributes.ReparsePoint)!=0)throw new TetherException(TetherError.Storage);}
    }
    private static void ValidateAncestors(string path)
    {
        var user=User;for(var parent=new DirectoryInfo(path).Parent;parent!=null;parent=parent.Parent){if(!parent.Exists)continue;var security=parent.GetAccessControl(AccessControlSections.Access);foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier))){if(rule.AccessControlType!=AccessControlType.Allow||(rule.PropagationFlags&PropagationFlags.InheritOnly)!=0)continue;var sid=(SecurityIdentifier)rule.IdentityReference;if(sid.Equals(user)||sid.IsWellKnown(WellKnownSidType.LocalSystemSid)||sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)||sid.Value.StartsWith("S-1-5-80-",StringComparison.Ordinal))continue;const FileSystemRights dangerous=FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;if((rule.FileSystemRights&dangerous)!=0)throw new TetherException(TetherError.Storage);}}
    }
    private static void ValidateHandle(SafeFileHandle handle)
    {
        if(!GetFileInformationByHandleEx(handle,9,out var attributes,8)||(attributes.Attributes&0x410)!=0)throw new TetherException(TetherError.Storage);
        if(GetSecurityInfo(handle,1,5,out _,IntPtr.Zero,out _,IntPtr.Zero,out var descriptor)!=0)throw new TetherException(TetherError.Storage);
        try{var length=GetSecurityDescriptorLength(descriptor);if(length is 0 or>65536)throw new TetherException(TetherError.Storage);var bytes=new byte[length];Marshal.Copy(descriptor,bytes,0,bytes.Length);var security=new RawSecurityDescriptor(bytes,0);var dacl=security.DiscretionaryAcl;if(security.Owner?.Equals(User)!=true||(security.ControlFlags&ControlFlags.DiscretionaryAclProtected)==0||dacl?.Count!=1||dacl[0] is not CommonAce ace||ace.AceQualifier!=AceQualifier.AccessAllowed||ace.AceFlags!=AceFlags.None||!ace.SecurityIdentifier.Equals(User)||ace.AccessMask!=0x1f01ff)throw new TetherException(TetherError.Storage);}finally{LocalFree(descriptor);}
    }
    internal static FileStream Read(string path)
    {
        NoReparse(path);ValidateAncestors(path);Validate(path,false);var handle=WithSecurity(attrs=>CreateFileW(path,0x80000000,1|2,ref attrs,3,0x80|0x00200000,IntPtr.Zero));if(handle.IsInvalid){handle.Dispose();throw new TetherException(TetherError.Storage);}try{ValidateHandle(handle);return new FileStream(handle,FileAccess.Read);}catch{handle.Dispose();throw;}
    }
    internal static void PrepareDirectory(string path)
    {
        try {
            NoReparse(path);ValidateAncestors(path);var missing=new Stack<string>();var current=new DirectoryInfo(path);while(!current.Exists){missing.Push(current.FullName);current=current.Parent??throw new TetherException(TetherError.Storage);}
            while(missing.Count>0){var next=missing.Pop();if(!WithSecurity(attrs=>CreateDirectoryW(next,ref attrs)))throw new TetherException(TetherError.Storage);Validate(next,true);}Validate(path,true);
        }catch(TetherException){throw;}catch{throw new TetherException(TetherError.Storage);}
    }
    internal static void Validate(string path,bool directory)
    {
        NoReparse(path);FileSystemSecurity security=directory?new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access):new FileInfo(path).GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access);
        var user=User;var rules=security.GetAccessRules(true,true,typeof(SecurityIdentifier));
        if(!security.AreAccessRulesProtected||security.GetOwner(typeof(SecurityIdentifier))?.Equals(user)!=true||rules.Count!=1||rules[0] is not FileSystemAccessRule rule||!rule.IdentityReference.Equals(user)||rule.IsInherited||rule.AccessControlType!=AccessControlType.Allow||rule.FileSystemRights!=FileSystemRights.FullControl||rule.InheritanceFlags!=InheritanceFlags.None||rule.PropagationFlags!=PropagationFlags.None)throw new TetherException(TetherError.Storage);
    }
    internal static FileStream Create(string path)=>Open(path,true);
    internal static FileStream OpenLock(string path) {if(File.Exists(path))return Open(path,false);try{return Open(path,true);}catch when(File.Exists(path)){return Open(path,false);}}
    private static FileStream Open(string path,bool create)
    {
        NoReparse(path);ValidateAncestors(path);if(!create)Validate(path,false);
        var handle=WithSecurity(attrs=>CreateFileW(path,0xC0000000,1|2,ref attrs,create?1u:3u,0x80|0x00200000,IntPtr.Zero));
        if(handle.IsInvalid){handle.Dispose();throw new TetherException(TetherError.Storage);}try{ValidateHandle(handle);return new FileStream(handle,FileAccess.ReadWrite);}catch{handle.Dispose();if(create&&File.Exists(path))File.Delete(path);throw;}
    }
}
internal static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)]private struct Blob{public int Length;public IntPtr Data;}
    [DllImport("crypt32.dll",SetLastError=true)]private static extern bool CryptProtectData(ref Blob input,IntPtr description,ref Blob entropy,IntPtr reserved,IntPtr prompt,uint flags,out Blob output);
    [DllImport("crypt32.dll",SetLastError=true)]private static extern bool CryptUnprotectData(ref Blob input,IntPtr description,ref Blob entropy,IntPtr reserved,IntPtr prompt,uint flags,out Blob output);
    [DllImport("kernel32.dll")]private static extern IntPtr LocalFree(IntPtr data);
    internal static byte[] Transform(byte[] bytes,string appId,bool decrypt)
    {
        if(bytes.Length>1_048_576)throw new TetherException(TetherError.Storage);
        var entropy=Encoding.UTF8.GetBytes("Tether.Windows.CurrentUser.v1/"+appId);var a=GCHandle.Alloc(bytes,GCHandleType.Pinned);var b=GCHandle.Alloc(entropy,GCHandleType.Pinned);
        Blob output=default;
        try {var input=new Blob{Length=bytes.Length,Data=a.AddrOfPinnedObject()};var extra=new Blob{Length=entropy.Length,Data=b.AddrOfPinnedObject()};
            bool ok=decrypt?CryptUnprotectData(ref input,IntPtr.Zero,ref extra,IntPtr.Zero,IntPtr.Zero,1,out output):CryptProtectData(ref input,IntPtr.Zero,ref extra,IntPtr.Zero,IntPtr.Zero,1,out output);
            if(!ok||output.Length<0||output.Length>1_064_960)throw new TetherException(TetherError.Storage);var result=new byte[output.Length];Marshal.Copy(output.Data,result,0,result.Length);return result;
        } finally {a.Free();b.Free();CryptographicOperations.ZeroMemory(entropy);if(output.Data!=IntPtr.Zero){if(output.Length is >=0 and <=1_064_960)Marshal.Copy(new byte[output.Length],0,output.Data,output.Length);LocalFree(output.Data);}}
    }
}
