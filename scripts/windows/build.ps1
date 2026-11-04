param([ValidateSet('Debug','Release')][string]$Configuration='Release',[string]$OutputDirectory,[switch]$SkipRust,[string]$DotNetPath='dotnet.exe')
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root 'artifacts/windows/x64'}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Output already exists; choose a fresh artifact directory to preserve prior evidence.'}
$stage=$OutputDirectory+'.stage-'+[Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $stage -Force | Out-Null
function Get-TetherSourceHashes {
    $files=@(Get-ChildItem (Join-Path $root 'crates') -Recurse -File|Where-Object {$_.Extension -in @('.rs','.toml','.h')})
    $files+=@(Get-ChildItem (Join-Path $root 'packages/windows') -Recurse -File|Where-Object {$_.Extension -in @('.cs','.csproj','.xaml','.manifest','.targets','.props') -and $_.FullName -notmatch '[\\/](bin|obj)[\\/]'})
    $files+=@(Get-ChildItem (Join-Path $root 'scripts/windows') -Filter '*.ps1' -File)
    foreach($name in @('Cargo.toml','Cargo.lock','LICENSE','THIRD_PARTY_NOTICES.txt')){$files+=Get-Item (Join-Path $root $name)}
    $result=@{};foreach($file in $files){$result[$file.FullName.Substring($root.Length+1).Replace('\','/')]=(Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()};return $result
}
$sourceBefore=Get-TetherSourceHashes
$previousEncodedRustFlags=$env:CARGO_ENCODED_RUSTFLAGS
$remapPaths=$Configuration -eq 'Release'
$managedBuildArguments=@()
if($remapPaths){
    if($env:RUSTFLAGS -and !$previousEncodedRustFlags){throw 'Use CARGO_ENCODED_RUSTFLAGS to preserve custom Rust flags in a release privacy build.'}
    $separator=[char]31;$flags=@();if($previousEncodedRustFlags){$flags+=@($previousEncodedRustFlags.Split($separator))}
    # Rust source/panic paths and the linker CodeView PDB reference need separate mappings.
    $prefixes=@($env:USERPROFILE,$env:HOME,$env:CARGO_HOME,$env:RUSTUP_HOME)|Where-Object {$_ -and [IO.Path]::IsPathRooted($_)}|Select-Object -Unique
    foreach($prefix in $prefixes){foreach($form in (@($prefix,$prefix.Replace('\','/'))|Select-Object -Unique)){$flags+='--remap-path-prefix='+$form+'=/_/home'}}
    foreach($form in (@($root,$root.Replace('\','/'))|Select-Object -Unique)){$flags+='--remap-path-prefix='+$form+'=/_/tether'}
    $flags+='-Clink-arg=/PDBALTPATH:%_PDB%'
    $env:CARGO_ENCODED_RUSTFLAGS=$flags -join $separator
    $managedBuildArguments=@("-p:PathMap=$root=/_/tether",'-p:Deterministic=true','-p:ContinuousIntegrationBuild=true')
}
Push-Location $root
try {
    $sdkVersion=& $DotNetPath --version
    if($LASTEXITCODE -or [int]($sdkVersion.Split('.')[0]) -lt 10){throw 'A supported .NET 10 SDK is required. Supply -DotNetPath for an isolated project-local installation.'}
    $rustHost=(& rustc.exe -vV | Select-String '^host: ').ToString().Substring(6)
    if($rustHost -ne 'x86_64-pc-windows-msvc'){throw 'This package script builds native Windows x64 MSVC artifacts only.'}
    $native=Join-Path $root ('target/'+$Configuration.ToLowerInvariant())
    if(-not $SkipRust){$tetherCargoArguments=@('build','--locked','-p','tether','-p','tether-ffi','-p','tether-relay','-j','2');if($Configuration -eq 'Release'){$tetherCargoArguments+='--release'};& cargo.exe @tetherCargoArguments;if($LASTEXITCODE){throw 'Native Rust build failed'}}
    foreach($notice in @('LICENSE','THIRD_PARTY_NOTICES.txt')){Copy-Item -LiteralPath (Join-Path $root $notice) -Destination $stage}
    foreach($name in @('tether.exe','tether_ffi.dll')){Copy-Item -LiteralPath (Join-Path $native $name) -Destination $stage}
    & $DotNetPath build packages/windows/Tether.Core.Tests/Tether.Core.Tests.csproj --no-incremental -m:1 -c $Configuration "-p:TetherNativeDir=$native" @managedBuildArguments
    if($LASTEXITCODE){throw 'Fresh Windows SDK compilation failed'}
    & $DotNetPath test packages/windows/Tether.Core.Tests/Tether.Core.Tests.csproj --no-build -m:1 -c $Configuration "-p:TetherNativeDir=$native" @managedBuildArguments
    if($LASTEXITCODE){throw 'Windows SDK tests failed'}
    & $DotNetPath build packages/windows/Tether.Sample.WinUI/Tether.Sample.WinUI.csproj --no-incremental -m:2 "-p:Configuration=$Configuration" -p:Platform=x64 "-p:TetherNativeDir=$native" "-p:OutputPath=$stage/sample/" @managedBuildArguments
    if($LASTEXITCODE){throw 'Native WinUI sample build failed'}
    $assets=Get-Content -Raw (Join-Path $root 'packages/windows/Tether.Sample.WinUI/obj/project.assets.json')|ConvertFrom-Json
    $packageRoots=@($assets.packageFolders.PSObject.Properties.Name)
    foreach($library in $assets.libraries.PSObject.Properties){if($library.Value.type -ne 'package'){continue};$packagePath=$null;foreach($packageRoot in $packageRoots){$candidate=Join-Path $packageRoot $library.Value.path;if(Test-Path $candidate){$packagePath=$candidate;break}};if(!$packagePath){throw ('Resolved package missing: '+$library.Name)}
        $notices=@(Get-ChildItem $packagePath -File|Where-Object {$_.Name -match '^(license|notice|third.party.notices|copyright)'})
        if($notices.Count){$destination=Join-Path $stage ('third-party/nuget/'+$library.Name);New-Item -ItemType Directory -Path $destination -Force|Out-Null;foreach($notice in $notices){Copy-Item -LiteralPath $notice.FullName -Destination $destination}}
    }
    & $DotNetPath pack packages/windows/Tether.Core/Tether.Core.csproj -c $Configuration -o (Join-Path $stage 'nuget') "-p:TetherNativeDir=$native" @managedBuildArguments
    if($LASTEXITCODE){throw 'Core SDK package failed'}
    & $DotNetPath pack packages/windows/Tether.WinUI/Tether.WinUI.csproj -m:2 "-p:Configuration=$Configuration" -p:Platform=x64 "-p:TetherNativeDir=$native" "-p:PackageOutputPath=$stage/nuget/" @managedBuildArguments
    if($LASTEXITCODE){throw 'WinUI package failed'}
    $sourceAfter=Get-TetherSourceHashes
    if($sourceBefore.Count -ne $sourceAfter.Count){throw 'Source population changed during packaging.'}
    foreach($path in $sourceBefore.Keys){if($sourceAfter[$path] -ne $sourceBefore[$path]){throw ('Source changed during packaging: '+$path)}}
    $hashes=@{};Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {$hashes[$_.FullName.Substring($stage.Length+1)]=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
    $coreProject=[xml](Get-Content -Raw (Join-Path $root 'packages/windows/Tether.Core/Tether.Core.csproj'));$uiProject=[xml](Get-Content -Raw (Join-Path $root 'packages/windows/Tether.WinUI/Tether.WinUI.csproj'));$versions=@{'Fledgeling.Tether.Windows'=$coreProject.SelectSingleNode('/Project/PropertyGroup/Version').InnerText.Trim();'Fledgeling.Tether.WinUI'=$uiProject.SelectSingleNode('/Project/PropertyGroup/Version').InnerText.Trim()}
    @{schema='tether.windows-artifacts/1';version=$versions['Fledgeling.Tether.WinUI'];packageVersions=$versions;architecture='x64';dotnetSdk=$sdkVersion;rustBuildSkipped=[bool]$SkipRust;pathRemapping=@{enabled=$remapPaths;rustSourcePrefixes=$remapPaths;rustPdbBasenameOnly=$remapPaths;managedPathMap=$remapPaths;nativeCCompiler='MSVC default; no unsupported prefix-map flag injected'};sourceFiles=$sourceBefore;rustHost=$rustHost;files=$hashes} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8
    if(Test-Path -LiteralPath $OutputDirectory){throw 'Output already exists; choose a fresh artifact directory to preserve prior evidence.'}
    Move-Item -LiteralPath $stage -Destination $OutputDirectory
    Write-Output ('Windows artifacts: '+$OutputDirectory)
} finally {$env:CARGO_ENCODED_RUSTFLAGS=$previousEncodedRustFlags;Pop-Location}
