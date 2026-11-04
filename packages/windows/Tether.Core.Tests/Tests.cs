using System.Security.AccessControl;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Xunit;
[assembly:SupportedOSPlatform("windows")]
[assembly:CollectionBehavior(DisableTestParallelization=true)]
namespace Tether.Core.Tests;
public sealed class ProtectedStorageTests
{
    private static string Root()=>Path.Combine(Path.GetTempPath(),"tether-sdk-test-"+Guid.NewGuid().ToString("N"));
    [Fact]public void App_scope_directories_are_case_distinct_and_dot_scopes_cannot_traverse()
    {Assert.NotEqual(Scope.ProfileDirectory("Case.App"),Scope.ProfileDirectory("case.app"));foreach(var app in new[]{".",".."})Assert.Equal(64,Path.GetFileName(Scope.ProfileDirectory(app)).Length);}
    [Fact]public void A_257th_pending_peer_is_refused_without_bricking_the_existing_256_records()
    {var root=Root();try{var store=new TetherProtectedStore("test.storage",root);for(int i=0;i<256;i++){var bytes=new byte[32];System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(bytes,i);var key=Convert.ToBase64String(bytes);store.Begin(new("test.storage",key,key,TetherRoute.Direct("127.0.0.1",7445),false,Guid.NewGuid()));}var before=Directory.EnumerateFiles(root,"peer-*.dpapi").ToDictionary(p=>Path.GetFileName(p)!,p=>SHA256.HashData(File.ReadAllBytes(p)));var other=Convert.ToBase64String(Enumerable.Repeat((byte)255,32).ToArray());Assert.Equal(TetherError.Storage,Assert.Throws<TetherException>(()=>store.Begin(new("test.storage",other,other,TetherRoute.Direct("127.0.0.1",7445),false,Guid.NewGuid()))).Code);Assert.Equal(256,store.Records().Count);foreach(var item in before)Assert.True(item.Value.SequenceEqual(SHA256.HashData(File.ReadAllBytes(Path.Combine(root,item.Key!)))));}finally{if(Directory.Exists(root))Directory.Delete(root,true);}}
    [Fact]public void A_foreign_delete_child_grant_on_an_ancestor_is_refused_without_rewriting_it()
    {var root=Root();var parent=Path.Combine(root,"parent");try{PrivateFiles.PrepareDirectory(parent);var child=Path.Combine(parent,"private");PrivateFiles.PrepareDirectory(child);var directory=new DirectoryInfo(parent);var acl=directory.GetAccessControl();acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid,null),System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles,System.Security.AccessControl.AccessControlType.Allow));directory.SetAccessControl(acl);var before=directory.GetAccessControl().GetSecurityDescriptorBinaryForm();Assert.Equal(TetherError.Storage,Assert.Throws<TetherException>(()=>new TetherProtectedStore("test.storage",child)).Code);Assert.True(before.SequenceEqual(directory.GetAccessControl().GetSecurityDescriptorBinaryForm()));}finally{if(Directory.Exists(root))Directory.Delete(root,true);}}
    [Fact]public void Current_user_identity_reopens_without_plaintext_key_at_rest()
    {
        var root=Root();try{var store=new TetherProtectedStore("test.storage",root);using var a=store.Identity();using var b=new TetherProtectedStore("test.storage",root).Identity();Assert.True(a.Public.SequenceEqual(b.Public));Assert.Empty(store.Records());var blob=File.ReadAllBytes(Path.Combine(root,"identity.dpapi"));Assert.True(blob.Length>32);var secret=Dpapi.Transform(blob,"test.storage",true);try{Assert.Equal(32,secret.Length);Assert.False(blob.AsSpan().IndexOf(secret)>=0);}finally{CryptographicOperations.ZeroMemory(secret);}}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
    [Fact]public void Corruption_and_cross_app_entropy_never_regenerate_trust()
    {
        var root=Root();try{var store=new TetherProtectedStore("test.storage",root);using var a=store.Identity();var path=Path.Combine(root,"identity.dpapi");var before=File.ReadAllBytes(path);Assert.Throws<TetherException>(()=>new TetherProtectedStore("other.app",root).Identity());Assert.True(File.ReadAllBytes(path).SequenceEqual(before));before[^1]^=1;File.WriteAllBytes(path,before);Assert.Throws<TetherException>(()=>store.Identity());Assert.True(File.ReadAllBytes(path).SequenceEqual(before));}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
    [Fact]public void Broad_inherited_directory_is_refused_without_changing_it()
    {var root=Root();Directory.CreateDirectory(root);try{Assert.Throws<TetherException>(()=>new TetherProtectedStore("test.storage",root));Assert.Empty(Directory.GetFiles(root));}finally{Directory.Delete(root,true);}}
    [Fact]public void Pending_and_confirmed_records_require_the_same_generation()
    {
        var root=Root();try{var store=new TetherProtectedStore("test.storage",root);var key=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));var peer=new PeerRecord("test.storage",key,key,TetherRoute.Direct("127.0.0.1",7445),false,Guid.NewGuid());store.Begin(peer);Assert.Throws<TetherException>(()=>store.Begin(peer));var confirmed=store.Confirm(peer);Assert.Throws<TetherException>(()=>store.Remove(peer,false));Assert.Single(store.Records());Assert.Throws<TetherException>(()=>store.Remove(confirmed with{PairingId=Guid.NewGuid()},true));store.Remove(confirmed,true);Assert.Empty(store.Records());}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
    [Fact]public void Route_replacement_is_compare_and_swap_and_keeps_identity()
    {
        var root=Root();try{var store=new TetherProtectedStore("test.storage",root);var key=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));var pending=new PeerRecord("test.storage",key,key,TetherRoute.Direct("127.0.0.1",7445),false,Guid.NewGuid());store.Begin(pending);var original=store.Confirm(pending);var replacement=original with{Route=TetherRoute.Direct("127.0.0.1",7446),PairingId=Guid.NewGuid()};store.ReplaceConfirmed(original,replacement);Assert.Equal(replacement,Assert.Single(store.Records()));Assert.Throws<TetherException>(()=>store.ReplaceConfirmed(original,replacement));Assert.Equal(original.HostKey,replacement.HostKey);}finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
}
public sealed class RustAbiTests
{
    [Fact]public void Noise_and_pairing_are_shared_rust_calls_not_platform_crypto()
    {
        using var ac=Native.Call(new(){{"command","identity.generate"}});using var bc=Native.Call(new(){{"command","identity.generate"}});using var a=new Identity(ac);using var b=new Identity(bc);
        using var an=Native.Call(new(){{"command","noise.new"},{"identity",a.Handle.Value},{"app","test.ffi"},{"role","client"}});using var bn=Native.Call(new(){{"command","noise.new"},{"identity",b.Handle.Value},{"app","test.ffi"},{"role","host"}});using var ah=new NativeHandle(Native.Handle(an.RootElement));using var bh=new NativeHandle(Native.Handle(bn.RootElement));
        byte[] Write(ulong h){using var r=Native.Call(new(){{"command","noise.write"},{"handle",h},{"data",Array.Empty<byte>()}});return Native.Data(r.RootElement);}void Read(ulong h,byte[] data){using var r=Native.Call(new(){{"command","noise.read"},{"handle",h},{"data",data}});}
        Read(bh.Value,Write(ah.Value));Read(ah.Value,Write(bh.Value));Read(bh.Value,Write(ah.Value));
        using var af=Native.Call(new(){{"command","noise.finish"},{"handle",ah.Take()}});using var bf=Native.Call(new(){{"command","noise.finish"},{"handle",bh.Take()}});using var at=new NativeHandle(Native.Handle(af.RootElement));using var bt=new NativeHandle(Native.Handle(bf.RootElement));Assert.True(Native.Data(af.RootElement,"binding",32).SequenceEqual(Native.Data(bf.RootElement,"binding",32)));
        var data=Encoding.UTF8.GetBytes("synthetic-native-ffi-frame");using var encrypted=Native.Call(new(){{"command","transport.encrypt"},{"handle",at.Value},{"data",data}});using var plain=Native.Call(new(){{"command","transport.decrypt"},{"handle",bt.Value},{"data",Native.Data(encrypted.RootElement)}});Assert.True(Native.Data(plain.RootElement).SequenceEqual(data));
        using var ap=Native.Call(new(){{"command","pairing.start"},{"role","client"},{"code","12345678"},{"app","test.ffi"},{"binding",Native.Data(af.RootElement,"binding",32)},{"clientKey",a.Public},{"hostKey",b.Public}});using var bp=Native.Call(new(){{"command","pairing.start"},{"role","host"},{"code","12345678"},{"app","test.ffi"},{"binding",Native.Data(bf.RootElement,"binding",32)},{"clientKey",a.Public},{"hostKey",b.Public}});using var aph=new NativeHandle(Native.Handle(ap.RootElement));using var bph=new NativeHandle(Native.Handle(bp.RootElement));
        using var ax=Native.Call(new(){{"command","pairing.finish"},{"handle",aph.Take()},{"data",Native.Data(bp.RootElement)}});using var bx=Native.Call(new(){{"command","pairing.finish"},{"handle",bph.Take()},{"data",Native.Data(ap.RootElement)}});using var axh=new NativeHandle(Native.Handle(ax.RootElement));using var bxh=new NativeHandle(Native.Handle(bx.RootElement));using var av=Native.Call(new(){{"command","pairing.verify"},{"handle",axh.Take()},{"data",Native.Data(bx.RootElement)}});using var bv=Native.Call(new(){{"command","pairing.verify"},{"handle",bxh.Take()},{"data",Native.Data(ax.RootElement)}});
    }
    [Fact]public void Invalid_rust_request_has_only_a_fixed_typed_error(){var e=Assert.Throws<TetherException>(()=>Native.Call(new(){{"command","not-a-command"},{"private","synthetic-canary"}}));Assert.DoesNotContain("synthetic-canary",e.Message);}
}
