<#
.SYNOPSIS
    ファイルサーバのアクセス権限(ACL)棚卸用インベントリ収集スクリプト(中断・再開対応)

.DESCRIPTION
    指定したルートパス配下をフォルダ単位で走査し、ACL情報をCSVに出力します。
    処理済みフォルダはチェックポイントファイルに記録されるため、
    中断後に同じコマンドを再実行すると続きから再開されます。

    既定ではフォルダのACLと「継承を無効化しているファイル」のACLのみ記録します。
    (継承されているファイルは親フォルダと同一権限のため、親フォルダの記録で代表できます)
    全ファイルを記録する場合は -IncludeAllFiles を指定してください。

.PARAMETER RootPath
    走査対象のルートパス(例: \\fileserver\share または D:\Shares)

.PARAMETER OutputDir
    出力先ディレクトリ(CSV・チェックポイント・エラーログを格納)

.PARAMETER IncludeAllFiles
    継承ACLのファイルも含め、全ファイルのACLを記録する

.PARAMETER TimeLimitMinutes
    指定分数を超えたら安全に中断する(0 = 無制限)。再実行で続きから再開。

.EXAMPLE
    .\Get-AclInventory.ps1 -RootPath "\\fs01\share" -OutputDir ".\output"

.EXAMPLE
    # 60分で自動中断、後日再実行で再開
    .\Get-AclInventory.ps1 -RootPath "\\fs01\share" -OutputDir ".\output" -TimeLimitMinutes 60
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootPath,

    [string]$OutputDir = ".\acl-output",

    [switch]$IncludeAllFiles,

    [int]$TimeLimitMinutes = 0
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path -LiteralPath $RootPath)) {
    Write-Error "RootPath が見つかりません: $RootPath"
    exit 1
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# ルートパスごとに別ファイルにする(複数共有を順に処理できるように)
$safeName       = ($RootPath -replace '[\\/:*?"<>|]', '_').Trim('_')
$csvPath        = Join-Path $OutputDir "acl_$safeName.csv"
$checkpointPath = Join-Path $OutputDir "checkpoint_$safeName.txt"
$errorLogPath   = Join-Path $OutputDir "errors_$safeName.log"

$startTime = Get-Date

# ---- チェックポイント読み込み(処理済みフォルダ一覧) ----
$done = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $checkpointPath) {
    foreach ($line in [System.IO.File]::ReadLines($checkpointPath)) {
        if ($line) { [void]$done.Add($line) }
    }
    Write-Host "チェックポイント検出: $($done.Count) フォルダ処理済み。続きから再開します。" -ForegroundColor Yellow
}

# ---- CSVヘッダ(新規時のみ) ----
$csvHeader = '"Path","Type","Owner","AccessControlType","IdentityReference","FileSystemRights","IsInherited","InheritanceFlags","PropagationFlags","AreAccessRulesProtected","ScannedAt"'
if (-not (Test-Path -LiteralPath $csvPath)) {
    Set-Content -LiteralPath $csvPath -Value $csvHeader -Encoding UTF8
}

# 追記用ライター(BOMなしUTF8だとExcelで文字化けするためUTF8 BOM)
$csvWriter = New-Object System.IO.StreamWriter($csvPath, $true, (New-Object System.Text.UTF8Encoding $true))
$cpWriter  = New-Object System.IO.StreamWriter($checkpointPath, $true, [System.Text.Encoding]::UTF8)
$errWriter = New-Object System.IO.StreamWriter($errorLogPath, $true, [System.Text.Encoding]::UTF8)

function Escape-Csv([string]$s) {
    if ($null -eq $s) { return '' }
    return $s -replace '"', '""'
}

function Write-AclRecord {
    param([string]$Path, [string]$Type)
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $protected = $acl.AreAccessRulesProtected
        $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        foreach ($ace in $acl.Access) {
            $line = '"{0}","{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}"' -f `
                (Escape-Csv $Path), $Type, (Escape-Csv $acl.Owner), $ace.AccessControlType, `
                (Escape-Csv $ace.IdentityReference.Value), (Escape-Csv $ace.FileSystemRights.ToString()), `
                $ace.IsInherited, $ace.InheritanceFlags, $ace.PropagationFlags, $protected, $ts
            $csvWriter.WriteLine($line)
        }
        return $protected
    }
    catch {
        $errWriter.WriteLine("{0}`t{1}`t{2}" -f (Get-Date -Format s), $Path, $_.Exception.Message)
        return $null
    }
}

# ---- フォルダ一覧の列挙(自身+全サブフォルダ) ----
Write-Host "フォルダ一覧を列挙中: $RootPath ..." -ForegroundColor Cyan
$allDirs = New-Object System.Collections.Generic.List[string]
$allDirs.Add($RootPath)
try {
    $opts = [System.IO.EnumerationOptions]::new()
    $opts.RecurseSubdirectories = $true
    $opts.IgnoreInaccessible   = $true
    $opts.AttributesToSkip     = [System.IO.FileAttributes]::ReparsePoint
    foreach ($d in [System.IO.Directory]::EnumerateDirectories($RootPath, '*', $opts)) {
        $allDirs.Add($d)
    }
}
catch {
    # PowerShell 5.1 (.NET Framework) では EnumerationOptions が無いためフォールバック
    Get-ChildItem -LiteralPath $RootPath -Directory -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $allDirs.Add($_.FullName) }
}
Write-Host "対象フォルダ数: $($allDirs.Count)(うち処理済み $($done.Count))" -ForegroundColor Cyan

# ---- メインループ ----
$processed = 0
$stopped = $false
try {
    foreach ($dir in $allDirs) {
        if ($done.Contains($dir)) { continue }

        # 時間制限チェック
        if ($TimeLimitMinutes -gt 0 -and ((Get-Date) - $startTime).TotalMinutes -ge $TimeLimitMinutes) {
            Write-Host "時間制限に到達。安全に中断します(再実行で再開)。" -ForegroundColor Yellow
            $stopped = $true
            break
        }

        # フォルダ自体のACL
        [void](Write-AclRecord -Path $dir -Type 'Directory')

        # フォルダ直下のファイル
        try {
            $files = [System.IO.Directory]::EnumerateFiles($dir)
            foreach ($f in $files) {
                if ($IncludeAllFiles) {
                    [void](Write-AclRecord -Path $f -Type 'File')
                }
                else {
                    # 継承を切っている(=独自権限を持つ)ファイルのみ記録
                    try {
                        $facl = Get-Acl -LiteralPath $f -ErrorAction Stop
                        if ($facl.AreAccessRulesProtected -or ($facl.Access | Where-Object { -not $_.IsInherited })) {
                            [void](Write-AclRecord -Path $f -Type 'File')
                        }
                    }
                    catch {
                        $errWriter.WriteLine("{0}`t{1}`t{2}" -f (Get-Date -Format s), $f, $_.Exception.Message)
                    }
                }
            }
        }
        catch {
            $errWriter.WriteLine("{0}`t{1}`t{2}" -f (Get-Date -Format s), $dir, $_.Exception.Message)
        }

        # フォルダ完了 → チェックポイント記録
        $cpWriter.WriteLine($dir)
        $processed++

        if ($processed % 100 -eq 0) {
            $csvWriter.Flush(); $cpWriter.Flush(); $errWriter.Flush()
            $pct = [math]::Round(($done.Count + $processed) / $allDirs.Count * 100, 1)
            Write-Progress -Activity "ACL収集中" -Status "$($done.Count + $processed) / $($allDirs.Count) ($pct%)" -PercentComplete $pct
        }
    }
}
finally {
    $csvWriter.Flush(); $csvWriter.Close()
    $cpWriter.Flush();  $cpWriter.Close()
    $errWriter.Flush(); $errWriter.Close()
}

Write-Progress -Activity "ACL収集中" -Completed
$elapsed = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
Write-Host ""
Write-Host "===== 結果 =====" -ForegroundColor Green
Write-Host "今回処理フォルダ数 : $processed"
Write-Host "累計処理フォルダ数 : $($done.Count + $processed) / $($allDirs.Count)"
Write-Host "経過時間           : $elapsed 分"
Write-Host "出力CSV            : $csvPath"
Write-Host "チェックポイント   : $checkpointPath"
Write-Host "エラーログ         : $errorLogPath"
if ($stopped) {
    Write-Host "※ 未完了です。同じコマンドを再実行すると続きから再開します。" -ForegroundColor Yellow
} else {
    Write-Host "完了しました。" -ForegroundColor Green
}
