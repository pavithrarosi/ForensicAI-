$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$dst=Join-Path $root 'data\datasets\SMS-Messages.xlsx'
$url='https://downloads.digitalcorpora.org/corpora/mobile/android_10/SMS-Messages.xlsx'
New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
Invoke-WebRequest -Uri $url -OutFile $dst
Write-Host "Downloaded: $dst"
Write-Host "Next: python scripts\train_android10_sms.py"
