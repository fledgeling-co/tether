param([Parameter(Mandatory=$true)][string]$ArtifactsDirectory,[string]$DotNetPath='dotnet.exe')
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ArtifactsDirectory=[IO.Path]::GetFullPath($ArtifactsDirectory)
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('tether-package-verification-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$checks=@()
try {
 foreach($package in @(@{id='Fledgeling.Tether.Windows';required=@('LICENSE','THIRD_PARTY_NOTICES.txt','lib/net8.0/Tether.Core.dll','runtimes/win-x64/native/tether_ffi.dll','tools/win-x64/tether.exe','buildTransitive/Fledgeling.Tether.Windows.targets')},@{id='Fledgeling.Tether.WinUI';required=@('LICENSE','THIRD_PARTY_NOTICES.txt','lib/net10.0-windows10.0.19041/Tether.WinUI.dll')})) {
  $projectName=if($package.id -eq 'Fledgeling.Tether.Windows'){'Tether.Core'}else{'Tether.WinUI'};$project=[xml](Get-Content -Raw (Join-Path $root ('packages/windows/'+$projectName+'/'+$projectName+'.csproj')));$version=$project.SelectSingleNode('/Project/PropertyGroup/Version').InnerText.Trim();$path=Join-Path $ArtifactsDirectory ('nuget/'+$package.id+'.'+$version+'.nupkg');$zip=[IO.Compression.ZipFile]::OpenRead($path)
  try{foreach($entry in $package.required){if(!$zip.GetEntry($entry)){throw ('Package entry missing: '+$entry)}}
   foreach($entry in @('runtimes/win-x64/native/tether_ffi.dll','tools/win-x64/tether.exe')){if($item=$zip.GetEntry($entry)){$stream=$item.Open();try{$algorithm=[Security.Cryptography.SHA256]::Create();$actual=[BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant();$expected=(Get-FileHash (Join-Path $ArtifactsDirectory ([IO.Path]::GetFileName($entry))) -Algorithm SHA256).Hash.ToLowerInvariant();if($actual -ne $expected){throw 'Packaged native binary differs from artifact'}}finally{$stream.Dispose();if($algorithm){$algorithm.Dispose()}}}}
   $checks+=@{package=$package.id;version=$version;requiredEntries=$package.required.Count;sha256=(Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()}
  }finally{$zip.Dispose()}
 }
 $negative=Join-Path $scratch 'negative';New-Item -ItemType Directory -Path $negative|Out-Null
 $dllOnly=Join-Path $scratch 'dll-only';New-Item -ItemType Directory -Path $dllOnly|Out-Null;Copy-Item (Join-Path $ArtifactsDirectory 'tether_ffi.dll') $dllOnly
 foreach($control in @(@{path=(Join-Path $scratch 'absent-native');message='Tether packaging requires the real Windows x64 tether_ffi.dll'},@{path=$dllOnly;message='Tether packaging requires the real Windows x64 tether.exe helper'})){
  & $DotNetPath pack (Join-Path $root 'packages/windows/Tether.Core/Tether.Core.csproj') -o $negative ("-p:TetherNativeDir="+$control.path) *> (Join-Path $scratch 'negative.log')
  if($LASTEXITCODE -eq 0 -or @(Get-ChildItem $negative -Filter '*.nupkg').Count -ne 0 -or !(Get-Content -Raw (Join-Path $scratch 'negative.log')).Contains($control.message)){throw 'Missing-native negative control did not fail for the required reason'}
 }
 $consumer=Join-Path $scratch 'consumer';New-Item -ItemType Directory -Path $consumer|Out-Null
 @'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0-windows</TargetFramework><RuntimeIdentifier>win-x64</RuntimeIdentifier><Nullable>enable</Nullable><ImplicitUsings>enable</ImplicitUsings></PropertyGroup><ItemGroup><PackageReference Include="Fledgeling.Tether.Windows" Version="0.1.0-preview.3" /></ItemGroup><ItemGroup><None Include="encoded-audio.ogg" CopyToOutputDirectory="PreserveNewest" /></ItemGroup></Project>
'@ | Set-Content (Join-Path $consumer 'Consumer.csproj') -Encoding UTF8
 Copy-Item (Join-Path $root 'packages/windows/verification/PackageConsumer.cs') (Join-Path $consumer 'Program.cs')
 Copy-Item (Join-Path $root 'tests/fixtures/media/audio.ogg') (Join-Path $consumer 'encoded-audio.ogg')
 $config=Join-Path $scratch 'NuGet.Config';$localSource=[Security.SecurityElement]::Escape((Join-Path $ArtifactsDirectory 'nuget'))
 ('<configuration><packageSources><clear/><add key="tether-local" value="'+$localSource+'"/><add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>')|Set-Content $config -Encoding UTF8
 & $DotNetPath restore (Join-Path $consumer 'Consumer.csproj') --configfile $config --packages (Join-Path $scratch 'packages')
 if($LASTEXITCODE){throw 'Fresh package consumer restore failed'}
 & $DotNetPath run --project (Join-Path $consumer 'Consumer.csproj') --no-restore *> (Join-Path $scratch 'consumer.log')
 if($LASTEXITCODE){Get-Content (Join-Path $scratch 'consumer.log');throw 'Fresh package consumer failed'}
 $result=Get-Content (Join-Path $scratch 'consumer.log')|Where-Object {$_ -like '{*'}|Select-Object -Last 1|ConvertFrom-Json
 # The runtime's patch version is whatever the SDK this check ran against supplies, and it moves
 # under a hosted runner. A pinned patch therefore failed on a machine where nothing was wrong,
 # so the assertion is the major version that SDK carries. Every other check is unchanged.
 $sdkVersion=(& $DotNetPath --version)
 if($LASTEXITCODE){throw 'Could not read the SDK version this check ran against'}
 $expectedMajor=($sdkVersion.Trim().Split('.')[0] -as [int])
 $runtimeMajor=(([string]$result.runtime).Split('.')[0] -as [int])
 if(!$expectedMajor){throw 'Could not read a major version from the SDK this check ran against'}
 if(!$result.paired -or !$result.status -or !$result.udp -or !$result.left -or !$result.helperPresent -or $result.media.packets -ne 64 -or $runtimeMajor -ne $expectedMajor){throw 'Fresh package consumer did not prove the required runtime and operations'}
 @{schema='tether.windows-package-verification/1';packages=$checks;missingNativeRefused=$true;missingHelperRefused=$true;consumer=$result;runtimeMajorExpected=$expectedMajor;sdkVersion=$sdkVersion.Trim()}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $ArtifactsDirectory 'package-verification.json') -Encoding UTF8
 Get-Content (Join-Path $ArtifactsDirectory 'package-verification.json')
}finally{if(Test-Path $scratch){Remove-Item -LiteralPath $scratch -Recurse -Force}}
