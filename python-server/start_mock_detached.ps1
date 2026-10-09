# start_mock_detached.ps1 -- start the mock server fully detached via WMI
# Why WMI: a plain Start-Process child dies with its parent PowerShell, so if the
#          driving command gets aborted the mock vanishes and the client then
#          only reports "network connection failed". Win32_Process::Create detaches.
# The server writes its own logfile (--logfile), so no shell redirection is
# involved and no cmd.exe wrapper is needed.
# NOTE: this file must stay ASCII-only. PS 5.1 reads BOM-less UTF-8 as ANSI and
#       garbled CJK bytes break quote pairing / parameter parsing.
param(
  [int]$Port = 8888,
  [int]$Algo = 0
)
$srv = 'E:\Test\Temp\yqlr\_out_rrcp\rrcp_server.py'
$cap = 'E:\Test\Temp\yqlr\_out_rrcp\capture\srv'
$tmp = 'C:\Users\ADMINI~1\AppData\Local\Temp\opencode'
$log = "$tmp\srv.txt"

Get-CimInstance Win32_Process -Filter "Name='python.exe'" -EA SilentlyContinue |
  Where-Object { $_.CommandLine -match 'rrcp_server|rrcp_hs2|rrcp_capture' } |
  ForEach-Object { taskkill /F /PID $_.ProcessId 2>&1 | Out-Null }
Start-Sleep -Seconds 2
Remove-Item $cap -Recurse -Force -EA SilentlyContinue
Remove-Item $log -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force -Path $cap | Out-Null

$py = (Get-Command python).Source
$cmd = '"' + $py + '" "' + $srv + '" --port ' + $Port + ' --algo ' + $Algo + ' --out "' + $cap + '" --logfile "' + $log + '" --quiet'
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
Start-Sleep -Seconds 6
Write-Host ('create rc=' + $r.ReturnValue + ' pid=' + $r.ProcessId)
Write-Host '--- log ---'
Get-Content $log -EA SilentlyContinue | Select-Object -Last 8
Write-Host '--- netstat ---'
netstat -ano | Select-String (':' + $Port)