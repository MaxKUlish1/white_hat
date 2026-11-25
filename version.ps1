# Сбор версий ПО на Windows — ТОЛЬКО ЧТЕНИЕ. Запуск: powershell -NoProfile -ExecutionPolicy Bypass -File version.ps1
$out = "versions_{0}_{1}.txt" -f $env:COMPUTERNAME, (Get-Date -f yyyy-MM-dd_HHmm)
& {
  "== host"; $env:COMPUTERNAME; Get-Date
  $os = Get-CimInstance Win32_OperatingSystem; "OS $($os.Caption) $($os.Version) build $($os.BuildNumber)"; "LastBoot $($os.LastBootUpTime)"
  "== packages_windows"
  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
    Where-Object DisplayName | Sort-Object DisplayName -Unique | ForEach-Object { "$($_.DisplayName) | $($_.DisplayVersion) | $($_.Publisher)" }
  "== hotfixes"; Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 | ForEach-Object { "$($_.HotFixID) $($_.InstalledOn)" }
  "== services"; Get-Service | Where-Object Status -eq Running | ForEach-Object { $_.Name }
  "== listening"; Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort -Unique | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" }
} | Out-File -Encoding utf8 $out
"готово: $out"
