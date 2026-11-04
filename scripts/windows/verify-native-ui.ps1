param([Parameter(Mandatory=$true)][string]$Sample,[Parameter(Mandatory=$true)][string]$Profile,[Parameter(Mandatory=$true)][string]$Output,[Parameter(Mandatory=$true)][string]$DotNetRoot)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if(Test-Path -LiteralPath $Profile){throw 'Native verification requires a fresh scratch profile.'}
if(Test-Path -LiteralPath $Output){throw 'Native verification requires a fresh output directory.'}
New-Item -ItemType Directory -Path $Output|Out-Null
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type @'
using System;using System.Runtime.InteropServices;public static class TetherForeground { [DllImport("user32.dll")]static extern IntPtr GetForegroundWindow();[DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);public static uint Read(){uint p;GetWindowThreadProcessId(GetForegroundWindow(),out p);return p;} }
'@
$before=[TetherForeground]::Read();$snapshots=@();$info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$Sample;$info.WorkingDirectory=Split-Path $Sample;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.Arguments='--profile-root "'+$Profile+'" --verify-output "'+$Output+'"';$info.EnvironmentVariables['DOTNET_ROOT_X64']=$DotNetRoot;$info.EnvironmentVariables['DOTNET_ROOT']=$DotNetRoot
$p=New-Object Diagnostics.Process;$p.StartInfo=$info
try {
 $startedUtc=[DateTime]::UtcNow
 if(!$p.Start()){throw 'Owned sample start failed'}
 $deadline=(Get-Date).AddSeconds(45)
 do {
  $p.Refresh();$handle=$p.MainWindowHandle
  if($handle -ne [IntPtr]::Zero){
   try {
    $window=[System.Windows.Automation.AutomationElement]::FromHandle($handle)
    if($window.Current.ProcessId -ne $p.Id){throw [Security.SecurityException]::new('Automation root belongs to another process.')}
    $elements=$window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition)
    $rows=@();foreach($element in $elements){$current=$element.Current;if(!$current.IsOffscreen -and $current.ProcessId -eq $p.Id -and ($current.AutomationId.StartsWith('tether.') -or $current.ControlType -eq [System.Windows.Automation.ControlType]::TabItem)){$rows+=@{id=$current.AutomationId;name=$current.Name;type=$current.ControlType.ProgrammaticName;enabled=$current.IsEnabled;keyboardFocusable=$current.IsKeyboardFocusable}}}
    if($rows.Count){$snapshots+=@{at=[DateTimeOffset]::UtcNow.ToString('O');elements=$rows}}
   } catch [System.Windows.Automation.ElementNotAvailableException] {} catch [System.InvalidOperationException] {}
  }
  Start-Sleep -Milliseconds 200
 } while(!$p.HasExited -and (Get-Date) -lt $deadline)
 if(!$p.HasExited){$p.Kill();throw 'Owned sample timeout'}
 if($p.ExitCode -ne 0){throw ('Owned sample exited with code '+$p.ExitCode+'.')}
 $after=[TetherForeground]::Read();if($before -ne $after){throw 'Foreground changed during background UI verification.'}
 $rows=@($snapshots|ForEach-Object {$_.elements})
 @{schema='tether.windows-uia/1';process=$p.Id;foregroundBefore=$before;foregroundAfter=$after;foregroundPreserved=$true;exit=$p.ExitCode;scope='External UIA names and focusable flags; no OS keyboard injection or screen-reader speech';snapshots=$snapshots}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'uia-raw.json') -Encoding UTF8
 foreach($expected in @(@{id='tether.hosts';name='Saved hosts'},@{id='tether.clients';name='Authorized clients'})){if(!@($rows|Where-Object {$_.id -eq $expected.id -and $_.name -eq $expected.name}).Count){throw ('Named list missing from native UIA: '+$expected.id)}}
 foreach($prefix in @('tether.host.','tether.client.')){if(!@($rows|Where-Object {$_.id.StartsWith($prefix) -and $_.name.Length -gt 16}).Count){throw ('Named native UIA row missing: '+$prefix)}}
 if(Test-Path (Join-Path $Output 'failure.json')){throw (Get-Content -Raw (Join-Path $Output 'failure.json'))}
 $witnessPath=Join-Path $Output 'native-ui.json'
 if(!(Test-Path -LiteralPath $witnessPath)){throw 'Native visual witness missing.'}
 if((Get-Item -LiteralPath $witnessPath).LastWriteTimeUtc -lt $startedUtc){throw 'Native visual witness predates this child launch.'}
 $witness=Get-Content -Raw -LiteralPath $witnessPath|ConvertFrom-Json
 $expectedFrames=@('hosts-wide','clients-wide','clients-narrow','clients-narrow-actions','hosts-narrow','hosts-narrow-actions','hosts-offline','hosts-revoked')
 if($witness.schema -ne 'tether.windows-native-ui/1' -or $witness.rowIdentityRefreshChecks -ne 2 -or @($witness.observations).Count -ne 8 -or $witness.foregroundPreserved -ne $true){throw 'Native visual witness did not pass the required two row checks, eight frames and foreground preservation.'}
 $frames=@($witness.observations|ForEach-Object {$_.frame});foreach($frame in $expectedFrames){if(@($frames|Where-Object {$_ -eq $frame}).Count -ne 1){throw ('Native visual witness frame missing or duplicated: '+$frame)}}
 @{schema='tether.windows-uia/1';process=$p.Id;foregroundBefore=$before;foregroundAfter=$after;foregroundPreserved=$true;exit=$p.ExitCode;nativeWitnessVerified=$true;harnessSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();scope='External UIA names, focusable flags and own-window captures; no OS keyboard injection or screen-reader speech';snapshots=$snapshots}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $Output 'uia.json') -Encoding UTF8
} catch { $_.Exception.ToString()|Set-Content (Join-Path $Output 'uia-error.txt');throw } finally {try{if(!$p.HasExited){$p.Kill()}}catch{}$p.Dispose()}
