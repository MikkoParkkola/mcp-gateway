# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# The Windows owner-only rows that need real machine state: a second, non-admin account, a mapped
# network drive, and FAT32 and exFAT volumes. CI runs it in pwsh from the repository root, in the
# lib-a leg of windows-lib-shards, with the shared lib test exe as its one argument.
param([Parameter(Mandatory = $true)][string]$Exe)
          $ErrorActionPreference = 'Stop'
          Add-MpPreference -ExclusionPath $env:RUNNER_TEMP
          $free = 68..90 | ForEach-Object { [char]$_ } | Where-Object { -not (Test-Path "${_}:\") }
          # Second user: Users only, never Administrators.
          $pass = 'Mg1!' + [guid]::NewGuid().ToString('N').Substring(0, 10)
          $account = New-LocalUser -Name mgw-probe -Password (ConvertTo-SecureString $pass -AsPlainText -Force) -AccountNeverExpires
          if ((Get-LocalGroupMember Administrators).Name -match 'mgw-probe') { throw 'mgw-probe is an administrator' }
          $sid = $account.SID.Value
          secedit /export /cfg "$env:RUNNER_TEMP\sec.inf" /areas USER_RIGHTS | Out-Null
          (Get-Content "$env:RUNNER_TEMP\sec.inf") -replace '^(SeInteractiveLogonRight = .*)$', "`$1,*$sid" | Set-Content "$env:RUNNER_TEMP\sec.inf"
          secedit /configure /db "$env:RUNNER_TEMP\sec.sdb" /cfg "$env:RUNNER_TEMP\sec.inf" /areas USER_RIGHTS | Out-Null
          Set-Service seclogon -StartupType Manual; Start-Service seclogon
          # Mapped network drive.
          $net = $free[0]
          net use "${net}:" \\localhost\C$
          if ($LASTEXITCODE -ne 0) { throw 'net use failed' }
          New-Item -ItemType Directory -Force "${net}:\mgw-net-root" | Out-Null
          # FAT32 and exFAT volumes.
          $vols = @(@{ fs = 'FAT32'; letter = $free[1] }, @{ fs = 'exFAT'; letter = $free[2] })
          foreach ($v in $vols) {
            $vhd = "$env:RUNNER_TEMP\mgw-$($v.fs).vhdx"
            @("create vdisk file=`"$vhd`" maximum=64 type=expandable", "select vdisk file=`"$vhd`"",
              'attach vdisk', 'create partition primary', "format fs=$($v.fs) quick",
              "assign letter=$($v.letter)") | Set-Content "$env:RUNNER_TEMP\dp.txt"
            diskpart /s "$env:RUNNER_TEMP\dp.txt"
            if ($LASTEXITCODE -ne 0) { throw "diskpart $($v.fs) failed" }
          }
          $env:MGW_PROBE_USER = 'mgw-probe'
          $env:MGW_PROBE_PASS = $pass
          $env:MGW_NET_ROOT = "${net}:\mgw-net-root"
          $env:MGW_FAT32_ROOT = "$($free[1]):\"
          $env:MGW_EXFAT_ROOT = "$($free[2]):\"
          # The shared exe, from the repository root as cargo ran it. At least five rows must run, so an
          # exe or a filter that stops matching cannot pass with none.
          $env:CARGO_MANIFEST_DIR = (Get-Location).Path
          & $Exe --ignored --show-output win_privileged:: 2>&1 | Tee-Object -Variable ran
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
          # The harness's own summary: the last line that starts with it, never a line a test printed.
          $summaries = [regex]::Matches(($ran -join "`n"), '(?m)^test result: ok\. (\d+) passed')
          $count = if ($summaries.Count) { $summaries[$summaries.Count - 1].Groups[1].Value } else { '' }
          if ([int]"0$count" -lt 5) { Write-Output "::error::the privileged rows ran $count tests; at least 5 must"; exit 1 }
