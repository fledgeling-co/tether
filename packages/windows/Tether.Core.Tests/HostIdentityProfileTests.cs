using Xunit;
namespace Tether.Core.Tests;

// The peer-identity proof the Rust helper and the Swift SDK already expose, reached through this SDK's own host profile.
// These cases need no host configuration, so they run wherever the managed suite runs, DPAPI available or not.
public sealed class HostIdentityProfileTests
{
    private const string Key=@"C:\ProgramData\example\router-identity.key";
    private static HostServiceProfile Tcp(string id,string? key=null)=>new(id,ServiceKind.Tcp,"127.0.0.1",8881,key);

    [Fact]public void An_identifying_profile_names_its_key_file()
    {Assert.Equal(new[]{"--identify","router="+Key},Tcp("router",Key).IdentityArguments);}

    [Fact]public void A_profile_without_a_key_file_asks_for_no_proof()
    {Assert.Empty(Tcp("api").IdentityArguments);}

    [Fact]public void A_UDP_service_cannot_be_identified()
    {Assert.Equal(TetherError.InvalidRoute,Assert.Throws<TetherException>(()=>new HostServiceProfile("audio",ServiceKind.Udp,"127.0.0.1",9000,Key).IdentityArguments).Code);}

    [Theory]
    [InlineData("https://example.com/key")]
    [InlineData("router-identity.key")]
    [InlineData(@"..\router-identity.key")]
    [InlineData("")]
    [InlineData("C:\\keys\\router\u0000.key")]
    // A UNC share would read the host's own secret over the network.
    [InlineData(@"\\server\share\router-identity.key")]
    [InlineData("//server/share/router-identity.key")]
    // The device namespace reaches volumes and devices a drive letter does not name.
    [InlineData(@"\\?\C:\keys\router-identity.key")]
    [InlineData(@"\\.\C:\keys\router-identity.key")]
    [InlineData(@"\\?\UNC\server\share\router-identity.key")]
    // An unnormalized path is refused rather than normalized, so what is checked is what is passed.
    [InlineData(@"C:\ProgramData\example\..\..\Windows\router-identity.key")]
    [InlineData(@"C:\ProgramData\.\router-identity.key")]
    [InlineData("C:/ProgramData/example/router-identity.key")]
    // Rooted but with no volume, and a volume this machine does not have as a fixed disk.
    [InlineData(@"\keys\router-identity.key")]
    [InlineData(@"4:\keys\router-identity.key")]
    public void Only_a_drive_letter_rooted_local_path_can_hold_the_key(string path)
    {Assert.Equal(TetherError.InvalidRoute,Assert.Throws<TetherException>(()=>Tcp("router",path).IdentityArguments).Code);}

    [Fact]public void A_volume_that_is_not_a_fixed_local_disk_is_refused()
    {
        var absent=Enumerable.Range('D','Z'-'D'+1).Select(c=>(char)c)
            .FirstOrDefault(c=>!DriveInfo.GetDrives().Any(d=>d.Name.StartsWith(c.ToString(),StringComparison.OrdinalIgnoreCase)));
        Assert.NotEqual('\0',absent);
        Assert.Equal(TetherError.InvalidRoute,Assert.Throws<TetherException>(()=>Tcp("router",absent+@":\keys\router-identity.key").IdentityArguments).Code);
    }

    [Fact]public void The_fixed_system_volume_is_accepted()
    {
        var system=Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))!;
        Assert.Equal(DriveType.Fixed,new DriveInfo(system).DriveType);
        var key=Path.Combine(system,"ProgramData","example","router-identity.key");
        Assert.Equal(new[]{"--identify","router="+key},Tcp("router",key).IdentityArguments);
    }

    [Fact]public void An_unacceptable_service_id_is_refused_before_its_key_file()
    {Assert.Equal(TetherError.InvalidScope,Assert.Throws<TetherException>(()=>Tcp("router/../api",Key).IdentityArguments).Code);}

    [Fact]public void Init_emits_every_service_then_each_identified_service_key()
    {
        var arguments=TetherHostController.InitArguments(@"C:\ProgramData\example\host.dpapi","example.app",
            new[]{Tcp("router",Key),new HostServiceProfile("audio",ServiceKind.Udp,"127.0.0.1",9000)});
        Assert.Equal(new[]{"host","init","--config",@"C:\ProgramData\example\host.dpapi","--app","example.app",
            "--service","router=tcp://127.0.0.1:8881","--service","audio=udp://127.0.0.1:9000","--identify","router="+Key},arguments);
    }

    [Fact]public void Init_without_an_identified_service_emits_no_identify_flag()
    {Assert.DoesNotContain("--identify",TetherHostController.InitArguments(@"C:\ProgramData\example\host.dpapi","example.app",new[]{Tcp("api")}));}

    [Fact]public void Every_identified_service_names_the_service_it_proves()
    {
        var second=@"C:\ProgramData\example\media-identity.key";
        var arguments=TetherHostController.InitArguments(@"C:\ProgramData\example\host.dpapi","example.app",
            new[]{Tcp("router",Key),new HostServiceProfile("media",ServiceKind.Tcp,"127.0.0.1",8882,second)});
        Assert.Equal(new[]{"--identify","router="+Key,"--identify","media="+second},arguments.Skip(10).ToArray());
        Assert.Equal(arguments.IndexOf("--identify"),arguments.LastIndexOf("--service")+2);
    }
}
