#Requires -Version 5.1

<#
.SYNOPSIS
Create a privacy-conscious diagnostic report for a Hikvision DVR disk or image.

.DESCRIPTION
Check the flat-index / first-leaf-chain policy in grub/grub-core/fs/hikvision.c and
write a JSON report explaining which recognition checks pass or fail. Footer
+0x18 comparisons are reported but no longer required for recognition. A null
MetadataChecksPassed means the diagnostic page budget prevented a decision.
Deep inspection compares index layouts and probes video-block headers automatically.

The script automatically performs bounded 4096-byte video-block probes; only
format hints are exported, never the bytes, decoded frames or video hashes.
Damaged metadata may point at unrelated sectors; only whitelisted numeric
fields and check results are reported.  By default the report also omits
the source path, raw bytes, channel numbers, recording timestamps, file names,
device identifiers, and hashes of video data.  Review the JSON before sharing
it; disk capacity and filesystem structure offsets are included because they
are needed to diagnose recognition failures.

Physical disks must be specified explicitly (for example,
\\.\PhysicalDrive2) and normally require an elevated PowerShell window.  The
source is opened read-only and with read/write sharing so no exclusive lock is
taken.

.PARAMETER SourcePath
Path to an image file or a raw disk such as \\.\PhysicalDrive2.

.PARAMETER OutputPath
Optional JSON report path.  If omitted, JSON is written to the pipeline.

.PARAMETER LogicalSectorSize
Logical sector size used for the same block-size alignment check as FsRover.
The default is 512.  Use 4096 if the source exposes 4 KiB logical sectors.

.PARAMETER BaseOffset
Filesystem start offset in bytes (for an image or disk containing partitions).
Defaults to zero. No automatic partition discovery or whole-disk scan.

.PARAMETER MaxTreePages
Maximum 4 KiB pages inspected per tree (default 256). Reports explicitly
indicate truncation. Both 48-byte and 40-byte entry layouts are checked as
hypotheses, not recovered files.

.PARAMETER SlowReadThresholdMilliseconds
Threshold for counting slow reads (default 100 ms). The report always retains
up to 32 slowest reads and 32 read failures, with byte offsets and durations.
Stage time includes parsing; read time includes seek/read and buffer handling.
Progress displays the current phase and read offset. This is not an I/O timeout:
a blocked synchronous device read still waits for Windows/device completion.

.PARAMETER MaxVideoProbes
Maximum video-block reads across both trees and geometry samples combined
(default 16, maximum 64), up to 4096 bytes each. Reports MPEG-PS / Annex-B
parameter-set signature hints; a match is not proof of playable video.

.PARAMETER IncludeFormatStrings
Include sanitized text from the fixed master signature and version fields.
This never includes video data, but is opt-in to keep the default report
minimal.

.EXAMPLE
.\scripts\Get-HikvisionDiagnostic.ps1 -SourcePath '\\.\PhysicalDrive2' `
    -OutputPath .\hikvision-deep.json

.EXAMPLE
.\scripts\Get-HikvisionDiagnostic.ps1 -SourcePath D:\private\hikvision.img `
    -OutputPath .\hikvision-diagnostic.json

.EXAMPLE
.\scripts\Get-HikvisionDiagnostic.ps1 -SourcePath '\\.\PhysicalDrive2' `
    -LogicalSectorSize 4096 -OutputPath .\hikvision-diagnostic.json
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory, Position = 0)]
	[string] $SourcePath,

	[Parameter()]
	[string] $OutputPath,

	[Parameter()]
	[ValidateSet(512, 1024, 2048, 4096)]
	[int] $LogicalSectorSize = 512,

	[Parameter()]
	[switch] $IncludeFormatStrings,

	[ValidateRange(0, 9223372036854775807)]
	[Int64] $BaseOffset = 0,

	[ValidateRange(1, 2048)]
	[int] $MaxTreePages = 256,
	[ValidateRange(1, 64)]
	[int] $MaxVideoProbes = 16,
	[ValidateRange(1, 60000)]
	[int] $SlowReadThresholdMilliseconds = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$masterOffset = [UInt64] 0x200
$masterSize = 0x100
$pageSize = [UInt64] 0x1000
$entrySize = 0x30
$entriesOffset = 0x60
$entriesMax = [int] [Math]::Floor(($pageSize - $entriesOffset) / $entrySize)
$recordingTimestamp = [UInt32] 0x7fffffff
$uint64Max = [UInt64]::MaxValue
$isDevice = $SourcePath.StartsWith('\\.\')
if ($isDevice -and $SourcePath -notmatch '^\\\\\.\\PhysicalDrive[0-9]+$') {
	throw 'Only explicit PhysicalDriveN device paths are supported.'
}
if ($BaseOffset % $LogicalSectorSize -ne 0) {
	throw 'BaseOffset must be aligned to LogicalSectorSize.'
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
	$fullOutputPath = [IO.Path]::GetFullPath($OutputPath)
	if ($fullOutputPath.StartsWith('\\.\') -or $fullOutputPath.StartsWith('\\?\')) {
		throw 'Output must be a new regular JSON file.'
	}
	if (Test-Path -LiteralPath $fullOutputPath) {
		throw 'Output already exists; choose a new report filename.'
	}
}
if ($isDevice -and -not ('HikDiagnosticNative' -as [type])) {
	Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class HikDiagnosticNative {
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint code,
        IntPtr input, uint inputSize, out long length, uint outputSize,
        out uint returned, IntPtr overlapped);
    public static long Length(SafeFileHandle h) {
        long length; uint returned;
        if (!DeviceIoControl(h, 0x7405c, IntPtr.Zero, 0, out length, 8,
            out returned, IntPtr.Zero) || returned != 8 || length < 0)
            throw new InvalidOperationException("Cannot query physical disk length.");
        return length;
    }
}
"@
}

function Add-Check {
	param (
		[Parameter(Mandatory)]
		[AllowEmptyCollection()]
		[System.Collections.Generic.List[object]] $Checks,
		[Parameter(Mandatory)] [string] $Name,
		[Parameter(Mandatory)] [bool] $Passed,
		[Parameter(Mandatory)] [string] $Detail
	)

	$Checks.Add([pscustomobject] [ordered]@{
		Name = $Name
		Passed = $Passed
		Detail = $Detail
	})
}

function Test-Range {
	param ([UInt64] $Offset, [UInt64] $Size, [UInt64] $Limit)

	return $Offset -le $Limit -and $Size -le ($Limit - $Offset)
}

function Test-TreeRange {
	param (
		[UInt64] $Base,
		[UInt64] $Size,
		[UInt64] $Offset,
		[UInt64] $Length
	)

	if ($Offset -lt $Base) {
		return $false
	}
	$relative = $Offset - $Base
	return $relative -le $Size -and $Length -le ($Size - $relative)
}

function Set-DiagnosticStage {
	param ([string] $Name)
	if ($null -ne $script:stageWatch) {
		$script:stageWatch.Stop()
		$script:stages.Add([pscustomobject][ordered]@{
			Name = $script:stageName
			ElapsedMilliseconds = [Math]::Round($script:stageWatch.Elapsed.TotalMilliseconds, 3)
			ReadCalls = $script:readCalls - $script:stageReadStart
			RequestedAlignedBytes = $script:readBytes - $script:stageByteStart
		})
	}
	$script:stageName = $Name
	$script:stageReadStart = $script:readCalls
	$script:stageByteStart = $script:readBytes
	$script:stageWatch = [Diagnostics.Stopwatch]::StartNew()
	Write-Progress -Activity 'Hikvision diagnostic' -Status $Name
}

function Read-SourceBytes {
	param (
		[Parameter(Mandatory)] [System.IO.FileStream] $Stream,
		[Parameter(Mandatory)] [UInt64] $Offset,
		[Parameter(Mandatory)] [int] $Count
	)

	$timer = [Diagnostics.Stopwatch]::StartNew()
	$success = $false
	$errorCode = $null
	$absolute = [decimal] $Offset + [decimal] $BaseOffset
	$readCount = $Count
	$script:readCalls++
	Write-Progress -Activity 'Hikvision diagnostic' -Status ('{0}: offset 0x{1:X}, {2} bytes' -f $script:stageName, $Offset, $Count)
	try {
		if (-not (Test-Range $Offset ([UInt64] $Count) $sourceLength)) {
			throw 'Requested metadata lies outside the selected source.'
		}
		$absolute = [decimal] $Offset + [decimal] $BaseOffset
		if ($absolute + $Count -gt [Int64]::MaxValue) {
			throw 'Read offset is larger than FileStream supports.'
		}
		$prefix = 0
		$readCount = $Count
		if ($isDevice) {
			$prefix = [int] ($absolute % $LogicalSectorSize)
			$absolute -= $prefix
			$readCount = [int] ([Math]::Ceiling(($prefix + $Count) / [double] $LogicalSectorSize) * $LogicalSectorSize)
		}
		$script:readBytes += [UInt64] $readCount
		[void] $Stream.Seek([Int64] $absolute, [System.IO.SeekOrigin]::Begin)
		$sectorBuffer = New-Object byte[] $readCount
		$done = 0
		while ($done -lt $readCount) {
			$read = $Stream.Read($sectorBuffer, $done, $readCount - $done)
			if ($read -eq 0) {
				throw 'Unexpected end of source while reading metadata.'
			}
			$done += $read
		}
		$buffer = New-Object byte[] $Count
		[Array]::Copy($sectorBuffer, $prefix, $buffer, 0, $Count)
		$success = $true
		return ,$buffer
	}
	catch {
		$errorCode = $_.Exception.HResult
		throw
	}
	finally {
		$timer.Stop()
		$elapsed = $timer.Elapsed.TotalMilliseconds
		$script:readMilliseconds += $elapsed
		if ($elapsed -ge $SlowReadThresholdMilliseconds) { $script:slowReadCount++ }
		$record = [pscustomobject][ordered]@{
			Stage = $script:stageName
			Offset = Format-HikOffset $Offset
			AlignedSourceOffset = $absolute.ToString('0', [Globalization.CultureInfo]::InvariantCulture)
			RequestedBytes = $Count; AlignedBytes = $readCount
			ElapsedMilliseconds = [Math]::Round($elapsed, 3)
			Succeeded = $success; HResult = $errorCode
		}
		$script:slowestReads = @(@($script:slowestReads) + @($record) | Sort-Object ElapsedMilliseconds -Descending | Select-Object -First 32)
		if (-not $success) {
			$script:failedReadCount++
			if ($script:readFailures.Count -lt 32) { $script:readFailures.Add($record) }
		}
	}
}

function Get-Le32 {
	param ([byte[]] $Bytes, [int] $Offset)
	return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Get-Le64 {
	param ([byte[]] $Bytes, [int] $Offset)
	return [BitConverter]::ToUInt64($Bytes, $Offset)
}

function Get-Be16 {
	param ([byte[]] $Bytes, [int] $Offset)
	return [UInt16] (([UInt16] $Bytes[$Offset] -shl 8) -bor $Bytes[$Offset + 1])
}

function Test-BytesEqual {
	param ([byte[]] $Bytes, [int] $Offset, [byte[]] $Expected)

	for ($i = 0; $i -lt $Expected.Length; $i++) {
		if ($Bytes[$Offset + $i] -ne $Expected[$i]) {
			return $false
		}
	}
	return $true
}

function Test-AllByte {
	param ([byte[]] $Bytes, [int] $Offset, [int] $Count, [byte] $Value)

	for ($i = 0; $i -lt $Count; $i++) {
		if ($Bytes[$Offset + $i] -ne $Value) {
			return $false
		}
	}
	return $true
}

function ConvertTo-SafeAscii {
	param ([byte[]] $Bytes, [int] $Offset, [int] $Count)

	$builder = New-Object System.Text.StringBuilder
	for ($i = 0; $i -lt $Count; $i++) {
		$value = $Bytes[$Offset + $i]
		if ($value -eq 0) {
			break
		}
		if ($value -ge 0x20 -and $value -le 0x7e) {
			[void] $builder.Append([char] $value)
		}
		else {
			[void] $builder.Append('?')
		}
	}
	return $builder.ToString()
}

function Format-HikOffset {
	param ([UInt64] $Value)
	return ('0x{0:X}' -f $Value)
}

# Deep inspection is independent of the driver's flat-tree recognition result.
function Get-HikDeepTree {
	param ($Stream, [UInt64] $Base, [UInt64] $Size, [UInt64] $Capacity,
		[UInt64] $VideoOffset, [UInt64] $BlockSize, [UInt32] $BlockCount)

	$rows = New-Object 'System.Collections.Generic.List[object]'
	$available = [int] [Math]::Floor($Size / 4096)
	$limit = [Math]::Min($available, $MaxTreePages)
	$summary = [ordered]@{
		Offset = Format-HikOffset $Base
		AvailableFullPages = $available
		AttemptedPages = $limit
		Truncated = ($limit -lt $available)
		Meaning = 'Layout and pointer candidates only; no tree traversal or recovery is asserted.'
		Pages = $rows
	}
	for ($n = 0; $n -lt $limit; $n++) {
		$offset = $Base + [UInt64] ($n * 4096)
		$row = [ordered]@{ RelativeOffset = Format-HikOffset ([UInt64] ($n * 4096)); ReadOK = $false }
		try { $bytes = Read-SourceBytes $Stream $offset 4096 }
		catch { $rows.Add([pscustomobject] $row); continue }
		$row.ReadOK = $true
		$count = Get-Le32 $bytes 0x10
		$row.DeclaredCountAt10 = $count
		$row.AllZero = Test-AllByte $bytes 0 4096 0
		$row.AllFF = Test-AllByte $bytes 0 4096 255
		$row.NextAt20 = Format-HikOffset (Get-Le64 $bytes 0x20)
		$layouts = New-Object 'System.Collections.Generic.List[object]'
		foreach ($stride in @(48, 40)) {
			$maximum = [int] [Math]::Floor((4096 - 96) / $stride)
			$layout = [ordered]@{
				Stride = $stride; CountFits = ($count -le $maximum)
				ExaminedEntries = 0; FFMarkers = 0; ZeroMarkers = 0
				VideoPointersAt20 = 0; TreePointerCandidates = @()
			}
			$edges = New-Object 'System.Collections.Generic.List[object]'
			if ($count -le $maximum) {
				$layout.ExaminedEntries = $count
				for ($j = 0; $j -lt $count; $j++) {
					$at = 96 + $j * $stride
					$marker = Test-AllByte $bytes $at 8 255
					if ($marker) { $layout.FFMarkers++ }
					if (Test-AllByte $bytes $at 8 0) { $layout.ZeroMarkers++ }
					# Export only values that resolve to aligned pages within this tree.
					foreach ($field in @(0, 8, 32)) {
						$value = Get-Le64 $bytes ($at + $field)
						if ((Test-TreeRange $Base $Size $value 4096) -and (($value - $Base) % 4096 -eq 0)) {
							$edges.Add([pscustomobject]@{ Entry = $j; Field = $field; TargetRelative = Format-HikOffset ($value - $Base) })
						}
					}
					$value = Get-Le64 $bytes ($at + 32)
					if ($marker -and $value -ge $VideoOffset -and (Test-Range $value $BlockSize $Capacity)) {
						$delta = $value - $VideoOffset
						if ($delta % $BlockSize -eq 0 -and ([decimal] $delta / $BlockSize) -lt $BlockCount) {
							$layout.VideoPointersAt20++
							if ($videoCandidates.Count -lt $MaxVideoProbes -and -not $videoCandidates.Contains($value)) {
								$videoCandidates.Add($value)
							}
						}
					}
				}
			}
			$layout.TreePointerCandidates = @($edges.ToArray())
			$layouts.Add([pscustomobject] $layout)
		}
		$row.Layouts = @($layouts.ToArray())
		$row.RoleHint = if ($count -gt 0 -and $layouts[0].FFMarkers -eq $count) { 'leaf-candidate' }
			elseif ($layouts[0].TreePointerCandidates.Count -gt 0) { 'index-candidate' } else { 'unknown' }
		$rows.Add([pscustomobject] $row)
	}
	return [pscustomobject] $summary
}

function Get-HikMediaHint {
	param ($Stream, [UInt64] $Offset, [UInt64] $BlockSize, [string] $Origin)
	$count = [int] [Math]::Min([decimal] 4096, [decimal] $BlockSize)
	$result = [ordered]@{
		Offset = Format-HikOffset $Offset; Origin = $Origin
		RequestedBytes = $count; ReadOK = $false; Hints = @()
	}
	$script:videoProbeAttempts++
	try { $bytes = Read-SourceBytes $Stream $Offset $count }
	catch { return [pscustomobject] $result }
	$result.ReadOK = $true
	$result.AllZero = Test-AllByte $bytes 0 $count 0
	$result.AllFF = Test-AllByte $bytes 0 $count 255
	$hits = @{}
	for ($i = 0; $i + 4 -le $count; $i++) {
		if ($bytes[$i] -ne 0 -or $bytes[$i+1] -ne 0 -or $bytes[$i+2] -ne 1) { continue }
		$h = $bytes[$i+3]
		$kind = $null
		if ($h -eq 0xba) { $kind = 'MPEG-PS pack start candidate' }
		elseif (($h -band 0x80) -eq 0 -and ($h -band 0x1f) -in @(7, 8)) {
			$kind = 'H.264 Annex-B parameter-set candidate'
		}
		elseif ($i + 5 -le $count -and ($h -band 0x80) -eq 0 -and (($h -shr 1) -band 63) -in @(32, 33, 34) -and ($bytes[$i+4] -band 7) -ne 0) {
			$kind = 'H.265 Annex-B parameter-set candidate'
		}
		if ($null -ne $kind -and -not $hits.ContainsKey($kind)) { $hits[$kind] = $i }
	}
	$result.Hints = @($hits.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Kind = $_; RelativeOffset = $hits[$_] } })
	return [pscustomobject] $result
}

function Get-HikLeafChainDiagnostic {
	param ($Stream, [UInt64] $Base, [UInt64] $Size, [UInt64] $FirstPage,
		[UInt64] $PageList, [UInt64] $FooterOffset, [UInt64] $FooterValue,
		[UInt64] $Capacity, [UInt64] $VideoOffset, [UInt64] $BlockSize, [UInt32] $BlockCount)

	$rows = New-Object 'System.Collections.Generic.List[object]'
	$seen = @{}
	$blocks = @{}
	$result = [ordered]@{
		MetadataChecksPassed = $false; Complete = $false; Truncated = $false
		Failure = $null; PageCount = 0; EntryCount = 0; ActiveEntryCount = 0
		UsableEntryCount = 0; SkippedEntryCount = 0; InvalidMarkers = 0
		InvalidDataOffsets = 0; ReservedChannelEntryCount = 0; InvalidTimestampEntryCount = 0
		DuplicateActiveBlockReferences = 0; UniqueActiveBlocks = 0
		TerminalPage = $null; FooterValueMatchesTerminal = $null
		FooterEqualityRequired = $false; Pages = $rows
	}
	$offset = $FirstPage
	while ($offset -ne $uint64Max) {
		if (-not (Test-TreeRange $Base $Size $offset 4096) -or
			($offset - $Base) % 4096 -ne 0 -or $offset -eq $Base -or
			$offset -eq $PageList -or $offset -eq $FooterOffset) {
			$result.Failure = 'invalid-leaf-pointer'; break
		}
		$key = $offset.ToString()
		if ($seen.ContainsKey($key)) { $result.Failure = 'cyclic-leaf-chain'; break }
		if ($rows.Count -ge $MaxTreePages) {
			$result.Truncated = $true
			$result.MetadataChecksPassed = $null
			$result.Failure = 'diagnostic-page-budget-exhausted'; break
		}
		$seen[$key] = $true
		try { $bytes = Read-SourceBytes $Stream $offset 4096 }
		catch { $result.Failure = 'leaf-read-failed'; break }
		$count = Get-Le32 $bytes 0x10
		$next = Get-Le64 $bytes 0x20
		$row = [ordered]@{
			Offset = Format-HikOffset $offset; RelativeOffset = Format-HikOffset ($offset - $Base)
			Count = $count; Next = Format-HikOffset $next
			InvalidMarkers = 0; InvalidDataOffsets = 0; ActiveEntries = 0; UsableEntries = 0
		}
		if ($count -gt $entriesMax) {
			$rows.Add([pscustomobject] $row)
			$result.Failure = 'invalid-leaf-count'; break
		}
		$result.EntryCount += $count
		for ($i = 0; $i -lt $count; $i++) {
			$at = 96 + $i * 48
			if (-not (Test-AllByte $bytes $at 8 255)) { $row.InvalidMarkers++; continue }
			if ((Get-Le64 $bytes ($at + 8)) -ne 0) { $result.SkippedEntryCount++; continue }
			$row.ActiveEntries++
			$value = Get-Le64 $bytes ($at + 32)
			$valid = $value -ge $VideoOffset -and (Test-Range $value $BlockSize $Capacity)
			if ($valid) {
				$delta = $value - $VideoOffset
				$valid = $delta % $BlockSize -eq 0 -and ([decimal] $delta / $BlockSize) -lt $BlockCount
			}
			if (-not $valid) { $row.InvalidDataOffsets++; continue }
			$blockKey = $value.ToString()
			if ($blocks.ContainsKey($blockKey)) { $result.DuplicateActiveBlockReferences++ }
			$blocks[$blockKey] = $true
			$channel = Get-Be16 $bytes ($at + 16)
			if ($channel -eq 0 -or $channel -ge 255) { $result.ReservedChannelEntryCount++; continue }
			$start = Get-Le32 $bytes ($at + 24)
			$end = Get-Le32 $bytes ($at + 28)
			if ($start -ne $recordingTimestamp -and ($start -eq 0 -or $start -ge $recordingTimestamp -or $end -eq 0 -or $end -ge $recordingTimestamp)) {
				$result.InvalidTimestampEntryCount++; continue
			}
			$row.UsableEntries++
		}
		$rows.Add([pscustomobject] $row)
		$result.ActiveEntryCount += $row.ActiveEntries
		$result.UsableEntryCount += $row.UsableEntries
		$result.InvalidMarkers += $row.InvalidMarkers
		$result.InvalidDataOffsets += $row.InvalidDataOffsets
		if ($row.InvalidMarkers -or $row.InvalidDataOffsets) { $result.Failure = 'invalid-leaf-entries'; break }
		if ($next -eq $uint64Max) {
			$result.TerminalPage = Format-HikOffset $offset
			$result.FooterValueMatchesTerminal = ($offset -eq $FooterValue)
			$result.Complete = $true
			$result.MetadataChecksPassed = $true
		}
		$offset = $next
	}
	$result.PageCount = $rows.Count
	$result.UniqueActiveBlocks = $blocks.Count
	$result.RecordCountMatchesBlockCount = ($result.EntryCount -eq $BlockCount)
	return [pscustomobject] $result
}

function Get-HikvisionTreeDiagnostic {
	param (
		[Parameter(Mandatory)] [System.IO.FileStream] $Stream,
		[Parameter(Mandatory)] [int] $Copy,
		[Parameter(Mandatory)] [UInt64] $Base,
		[Parameter(Mandatory)] [UInt64] $Size,
		[Parameter(Mandatory)] [UInt64] $Capacity,
		[Parameter(Mandatory)] [UInt64] $VideoOffset,
		[Parameter(Mandatory)] [UInt64] $BlockSize,
		[Parameter(Mandatory)] [UInt32] $BlockCount
	)

	$checks = New-Object 'System.Collections.Generic.List[object]'
	$result = [ordered]@{
		Copy = $Copy
		Present = ($Size -ne 0)
		Offset = (Format-HikOffset $Base)
		Size = [UInt64] $Size
		Recognized = $false
		Mode = 'flat-page-list'
		FooterEqualityRequired = $false
		PageCount = 0
		EntryCount = 0
		ActiveEntryCount = 0
		UsableEntryCount = 0
		SkippedEntryCount = 0
		Checks = $checks
	}

	if ($Size -eq 0) {
		Add-Check $checks 'tree-present' $false 'This HIKBTREE copy is absent.'
		return [pscustomobject] $result
	}

	$rangeValid = $Size -ge ($pageSize * 3) -and (Test-Range $Base $Size $Capacity)
	Add-Check $checks 'tree-range' $rangeValid 'Tree must span at least three pages and fit within the declared capacity.'
	if (-not $rangeValid) {
		return [pscustomobject] $result
	}

	try {
		$header = Read-SourceBytes $Stream $Base 0x60
	}
	catch {
		Add-Check $checks 'tree-header-read' $false 'Metadata read failed (I/O, bounds, or truncated source).'
		return [pscustomobject] $result
	}

	$treeSignature = [Text.Encoding]::ASCII.GetBytes('HIKBTREE')
	$signatureMatch = Test-BytesEqual $header 0x10 $treeSignature
	Add-Check $checks 'tree-signature' $signatureMatch 'Expected HIKBTREE at header +0x10.'
	if (-not $signatureMatch) {
		return [pscustomobject] $result
	}

	$footerOffset = Get-Le64 $header 0x40
	$pageList = Get-Le64 $header 0x50
	$firstPage = Get-Le64 $header 0x58
	$result.FooterOffset = Format-HikOffset $footerOffset
	$result.PageListOffset = Format-HikOffset $pageList
	$result.FirstPageOffset = Format-HikOffset $firstPage

	$pointersValid = (Test-TreeRange $Base $Size $footerOffset 0x20) -and
		(Test-TreeRange $Base $Size $pageList $pageSize) -and
		(Test-TreeRange $Base $Size $firstPage $pageSize) -and
		(($footerOffset - $Base) % $pageSize -eq 0) -and
		(($pageList - $Base) % $pageSize -eq 0) -and
		(($firstPage - $Base) % $pageSize -eq 0)
	Add-Check $checks 'tree-pointers' $pointersValid 'Footer, page-list, and first-page pointers must be page-aligned and inside this tree.'
	if (-not $pointersValid) {
		return [pscustomobject] $result
	}

	try {
		$footer = Read-SourceBytes $Stream $footerOffset 0x20
		$footerMarkerValid = Test-AllByte $footer 0x10 8 0xff
		$footerLast = Get-Le64 $footer 0x18
		$result.FooterValueAt18 = Format-HikOffset $footerLast
	}
	catch {
		Add-Check $checks 'footer-read' $false 'Footer read failed.'
		return [pscustomobject] $result
	}
	Add-Check $checks 'footer-marker' $footerMarkerValid 'Footer +0x10 must contain eight FF bytes; +0x18 equality is not required.'
	if (-not $footerMarkerValid) { return [pscustomobject] $result }

	try {
		$pageListHeader = Read-SourceBytes $Stream $pageList 0x60
		$pageCount = Get-Le32 $pageListHeader 0x10
	}
	catch {
		Add-Check $checks 'page-list-read' $false 'Metadata read failed (I/O, bounds, or truncated source).'
		return [pscustomobject] $result
	}
	$result.PageCount = $pageCount
	$pageCountValid = $pageCount -gt 0 -and $pageCount -le $entriesMax -and $pageCount -le ($Size / $pageSize)
	Add-Check $checks 'page-count' $pageCountValid 'Page count must be nonzero and fit both the page-list and tree.'
	if (-not $pageCountValid) {
		return [pscustomobject] $result
	}

	$pages = New-Object 'System.Collections.Generic.List[UInt64]'
	$pageSet = @{}
	for ($i = 0; $i -lt $pageCount; $i++) {
		try {
			$raw = Read-SourceBytes $Stream ($pageList + [UInt64] $entriesOffset + [UInt64] ($i * $entrySize)) $entrySize
			$page = Get-Le64 $raw 0
		}
		catch {
			Add-Check $checks 'page-list-entries' $false 'Metadata read failed (I/O, bounds, or truncated source).'
			return [pscustomobject] $result
		}
		$key = $page.ToString('X16')
		$pageValid = (Test-TreeRange $Base $Size $page $pageSize) -and
			(($page - $Base) % $pageSize -eq 0) -and -not $pageSet.ContainsKey($key)
		if (-not $pageValid) {
			Add-Check $checks 'page-list-entries' $false ('Page-list item {0} is out of range, unaligned, or duplicated.' -f $i)
			return [pscustomobject] $result
		}
		$pages.Add($page)
		$pageSet[$key] = $i
	}
	Add-Check $checks 'page-list-entries' $true 'All listed data pages are unique, aligned, and inside the tree.'

	$result.ListedPages = @($pages | ForEach-Object { Format-HikOffset $_ })
	foreach ($page in $pages) {
		try {
			$head = Read-SourceBytes $Stream $page 144
			$count = Get-Le32 $head 0x10
			$target = Get-Le64 $head 0x60
		}
		catch {
			Add-Check $checks 'listed-page-read' $false 'Listed page read failed.'
			return [pscustomobject] $result
		}
		if ($count -gt 0 -and $count -le $entriesMax -and
			-not (Test-AllByte $head 96 8 255) -and
			(Test-TreeRange $Base $Size $target 4096) -and ($target - $Base) % 4096 -eq 0) {
			$result.Mode = 'first-leaf-chain'
			$result.IndexPageTrigger = Format-HikOffset $page
			$chain = Get-HikLeafChainDiagnostic $Stream $Base $Size $firstPage $pageList $footerOffset $footerLast $Capacity $VideoOffset $BlockSize $BlockCount
			$result.LeafChain = $chain
			$result.Recognized = $chain.MetadataChecksPassed
			return [pscustomobject] $result
		}
	}

	$next = New-Object 'System.Collections.Generic.List[UInt64]'
	$invalidMarkerCount = 0
	$invalidOffsetCount = 0
	$reservedChannelCount = 0
	$invalidTimestampCount = 0
	for ($i = 0; $i -lt $pages.Count; $i++) {
		try {
			$pageHeader = Read-SourceBytes $Stream $pages[$i] $entriesOffset
			$entryCount = Get-Le32 $pageHeader 0x10
			$next.Add((Get-Le64 $pageHeader 0x20))
		}
		catch {
			Add-Check $checks 'data-pages' $false 'Metadata read failed (I/O, bounds, or truncated source).'
			return [pscustomobject] $result
		}
		if ($entryCount -gt $entriesMax) {
			Add-Check $checks 'data-pages' $false ('Data page {0} has too many entries.' -f $i)
			return [pscustomobject] $result
		}
		$result.EntryCount += $entryCount
		for ($j = 0; $j -lt $entryCount; $j++) {
			$entryOffset = $pages[$i] + [UInt64] $entriesOffset + [UInt64] ($j * $entrySize)
			try {
				$entry = Read-SourceBytes $Stream $entryOffset $entrySize
			}
			catch {
				Add-Check $checks 'data-pages' $false 'Metadata read failed (I/O, bounds, or truncated source).'
				return [pscustomobject] $result
			}
			if (-not (Test-AllByte $entry 0 8 0xff)) {
				$invalidMarkerCount++
				continue
			}
			$status = Get-Le64 $entry 0x08
			if ($status -ne 0) {
				$result.SkippedEntryCount++
				continue
			}
			$result.ActiveEntryCount++
			$channel = Get-Be16 $entry 0x10
			$start = Get-Le32 $entry 0x18
			$end = Get-Le32 $entry 0x1c
			$dataOffset = Get-Le64 $entry 0x20
			$offsetValid = $dataOffset -ge $VideoOffset
			if ($offsetValid) {
				$delta = $dataOffset - $VideoOffset
				$index = [decimal] $delta / [decimal] $BlockSize
				$offsetValid = ($delta % $BlockSize -eq 0) -and $index -lt $BlockCount -and
					(Test-Range $dataOffset $BlockSize $Capacity)
			}
			if (-not $offsetValid) {
				$invalidOffsetCount++
				continue
			}
			if ($channel -eq 0 -or $channel -ge 255) {
				$reservedChannelCount++
				continue
			}
			$timeValid = $start -eq $recordingTimestamp -or
				(($start -ne 0 -and $start -lt $recordingTimestamp) -and
				($end -ne 0 -and $end -lt $recordingTimestamp))
			if (-not $timeValid) {
				$invalidTimestampCount++
				continue
			}
			$result.UsableEntryCount++
		}
	}
	Add-Check $checks 'data-pages' $true 'All data-page headers and entry arrays were readable.'
	Add-Check $checks 'entry-markers' ($invalidMarkerCount -eq 0) ('Invalid marker count: {0}.' -f $invalidMarkerCount)
	Add-Check $checks 'entry-data-offsets' ($invalidOffsetCount -eq 0) ('Invalid active data-offset count: {0}.' -f $invalidOffsetCount)
	$result.ReservedChannelEntryCount = $reservedChannelCount
	$result.InvalidTimestampEntryCount = $invalidTimestampCount

	$incoming = New-Object int[] $pages.Count
	$terminalCount = 0
	$terminal = -1
	$chainTargetsValid = $true
	for ($i = 0; $i -lt $pages.Count; $i++) {
		if ($next[$i] -eq $uint64Max) {
			$terminalCount++
			$terminal = $i
			continue
		}
		$key = $next[$i].ToString('X16')
		if (-not $pageSet.ContainsKey($key)) {
			$chainTargetsValid = $false
			continue
		}
		$target = [int] $pageSet[$key]
		$incoming[$target]++
		if ($incoming[$target] -gt 1) {
			$chainTargetsValid = $false
		}
	}
	Add-Check $checks 'page-chain-targets' $chainTargetsValid 'Every next pointer must target one listed page and have at most one incoming edge.'

	$result.NextPointers = @($next | ForEach-Object { Format-HikOffset $_ })
	$headCount = @($incoming | Where-Object { $_ -eq 0 }).Count
	$terminalMatches = $terminalCount -eq 1 -and $terminal -ge 0
	$result.FooterValueMatchesTerminal = $terminalMatches -and $pages[$terminal] -eq $footerLast
	Add-Check $checks 'page-chain-endpoints' ($headCount -eq 1 -and $terminalMatches) 'The chain must have one head and one terminal page; footer equality is diagnostic only.'

	$chainComplete = $false
	if ($chainTargetsValid -and $headCount -eq 1 -and $terminalMatches) {
		$head = -1
		for ($i = 0; $i -lt $incoming.Length; $i++) {
			if ($incoming[$i] -eq 0) {
				$head = $i
				break
			}
		}
		$seen = New-Object bool[] $pages.Count
		$visited = 0
		while ($head -ge 0 -and $head -lt $pages.Count -and -not $seen[$head]) {
			$seen[$head] = $true
			$visited++
			if ($next[$head] -eq $uint64Max) {
				$head = -1
			}
			else {
				$head = [int] $pageSet[$next[$head].ToString('X16')]
			}
		}
		$chainComplete = $head -eq -1 -and $visited -eq $pages.Count
	}
	Add-Check $checks 'page-chain-complete' $chainComplete 'Walking next pointers must visit every listed page exactly once.'

	$result.Recognized = $signatureMatch -and $pointersValid -and $pageCountValid -and
		$chainTargetsValid -and $footerMarkerValid -and $headCount -eq 1 -and
		$terminalMatches -and $chainComplete -and $invalidMarkerCount -eq 0 -and
		$invalidOffsetCount -eq 0
	return [pscustomobject] $result
}

$sha = [Security.Cryptography.SHA256]::Create()
try {
	$scriptHash = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($PSCommandPath))).Replace('-', '').ToLowerInvariant()
}
finally { $sha.Dispose() }
$videoCandidates = New-Object 'System.Collections.Generic.List[UInt64]'
$script:videoProbeAttempts = 0
$script:readCalls = 0
$script:readBytes = [UInt64] 0
$script:stageWatch = $null
$script:stageName = 'initialization'
$script:stages = New-Object 'System.Collections.Generic.List[object]'
$script:slowestReads = @()
$script:readFailures = New-Object 'System.Collections.Generic.List[object]'
$script:failedReadCount = 0
$script:slowReadCount = 0
$script:readMilliseconds = 0.0
$totalWatch = [Diagnostics.Stopwatch]::StartNew()
$stream = $null
try {
	Set-DiagnosticStage 'source-open-and-length'
	$stream = [System.IO.File]::Open(
		$SourcePath,
		[System.IO.FileMode]::Open,
		[System.IO.FileAccess]::Read,
		[System.IO.FileShare]::ReadWrite)

	$deviceLength = if ($isDevice) { [HikDiagnosticNative]::Length($stream.SafeFileHandle) } else { $stream.Length }
	if ($BaseOffset -gt $deviceLength) { throw 'BaseOffset is beyond the source.' }
	$sourceLength = [UInt64] ($deviceLength - $BaseOffset)
	$checks = New-Object 'System.Collections.Generic.List[object]'
	$report = [ordered]@{
		SchemaVersion = 5
		Limitations = 'Metadata checks reproduce the driver; deep inspection and media hints are diagnostic only. Allocation failures and concurrent DVR writes are not tested. No automatic partition scan; BaseOffset selects a filesystem origin.'
		Generator = 'Get-HikvisionDiagnostic.ps1'
		DriverPolicy = 'metadata-only recognition; flat-or-first-leaf-chain; footer +0x18 equality diagnostic only'
		ScriptSHA256 = $scriptHash
		PowerShellVersion = $PSVersionTable.PSVersion.ToString()
		ReadBudget = [ordered]@{ MaxTreePagesPerPass = $MaxTreePages; MaxVideoProbes = $MaxVideoProbes; BytesPerVideoProbe = 4096 }
		GeneratedUtc = [DateTime]::UtcNow.ToString('o')
		Privacy = [ordered]@{
			VideoPayloadProbed = $false
			VideoHeaderProbingEnabled = $true
			FormatStringsIncluded = [bool] $IncludeFormatStrings
			SourcePathIncluded = $false
			RawBytesIncluded = $false
			ChannelNumbersIncluded = $false
			RecordingTimestampsIncluded = $false
			Notice = 'Review before sharing: disk size and filesystem structure offsets are included.'
		}
		Source = [ordered]@{
			Kind = $(if ($SourcePath -like '\\.\PhysicalDrive*') { 'physical-disk' } else { 'image-or-device-file' })
			Length = $sourceLength
			LogicalSectorSize = $LogicalSectorSize
			BaseOffset = $BaseOffset
		}
		Master = $null
		Trees = @()
		MetadataChecksPassed = $false
		Checks = $checks
	}

	Set-DiagnosticStage 'master'
	$masterRangeValid = Test-Range $masterOffset $masterSize $sourceLength
	Add-Check $checks 'master-range' $masterRangeValid 'The 256-byte master record at offset 0x200 must fit in the source.'
	if (-not $masterRangeValid) {
		$report | ConvertTo-Json -Depth 12 | ForEach-Object { $json = $_ }
	}
	else {
		$raw = Read-SourceBytes $stream $masterOffset $masterSize
		$signature = [Text.Encoding]::ASCII.GetBytes('HIKVISION@HANGZHOU')
		$version = [Text.Encoding]::ASCII.GetBytes('HIK.2011.03.08')
		$signatureMatch = Test-BytesEqual $raw 0x10 $signature
		$versionMatch = Test-BytesEqual $raw 0x30 $version
		Add-Check $checks 'master-signature' $signatureMatch 'Expected HIKVISION@HANGZHOU at master +0x10.'
		Add-Check $checks 'master-version' $versionMatch 'The current driver accepts only HIK.2011.03.08 at master +0x30.'

		$capacity = Get-Le64 $raw 0x48
		$logOffset = Get-Le64 $raw 0x60
		$logSize = Get-Le64 $raw 0x68
		$videoOffset = Get-Le64 $raw 0x78
		$blockSize = Get-Le64 $raw 0x88
		$blockCount = Get-Le32 $raw 0x90
		$tree1Offset = Get-Le64 $raw 0x98
		$tree1Size = Get-Le32 $raw 0xa0
		$tree2Offset = Get-Le64 $raw 0xa8
		$tree2Size = Get-Le32 $raw 0xb0

		$master = [ordered]@{
			SignatureMatch = $signatureMatch
			VersionMatch = $versionMatch
			Capacity = $capacity
			LogOffset = Format-HikOffset $logOffset
			LogSize = $logSize
			VideoOffset = Format-HikOffset $videoOffset
			BlockSize = $blockSize
			BlockCount = $blockCount
			Tree1Offset = Format-HikOffset $tree1Offset
			Tree1Size = $tree1Size
			Tree2Offset = Format-HikOffset $tree2Offset
			Tree2Size = $tree2Size
		}
		if ($IncludeFormatStrings) {
			$master.ObservedSignature = ConvertTo-SafeAscii $raw 0x10 0x20
			$master.ObservedVersion = ConvertTo-SafeAscii $raw 0x30 0x18
		}
		$report.Master = $master

		$geometryValid = $capacity -ge ($masterOffset + $masterSize) -and
			$capacity -le $sourceLength -and $blockSize -ne 0 -and
			$blockSize % $LogicalSectorSize -eq 0 -and $blockCount -ne 0 -and
			$videoOffset -lt $capacity
		if ($geometryValid) {
			$geometryValid = $blockCount -le ([decimal] ($capacity - $videoOffset) / [decimal] $blockSize)
		}
		Add-Check $checks 'master-geometry' $geometryValid 'Capacity, video offset, block size/count, and logical-sector alignment must match driver constraints.'

		$rangesValid = $geometryValid
		if ($rangesValid) {
			$blocksEnd = $videoOffset + ([UInt64] $blockCount * $blockSize)
			$rangesValid = $blocksEnd -le $capacity -and
				($logSize -eq 0 -or (Test-Range $logOffset $logSize $capacity))
			foreach ($tree in @(@($tree1Offset, [UInt64] $tree1Size), @($tree2Offset, [UInt64] $tree2Size))) {
				if ($tree[1] -ne 0 -and (-not (Test-Range $tree[0] $tree[1] $capacity) -or $tree[0] -lt $blocksEnd)) {
					$rangesValid = $false
				}
			}
			if ($tree1Size -eq 0 -and $tree2Size -eq 0) {
				$rangesValid = $false
			}
		}
		Add-Check $checks 'master-ranges' $rangesValid 'Log/tree ranges must fit the declared capacity; trees must follow all video blocks and at least one tree must exist.'

		if ($signatureMatch -and $versionMatch -and $geometryValid -and $rangesValid) {
			Set-DiagnosticStage 'primary-tree'
			$tree1 = Get-HikvisionTreeDiagnostic $stream 1 $tree1Offset $tree1Size $capacity $videoOffset $blockSize $blockCount
			Set-DiagnosticStage 'backup-tree'
			$tree2 = Get-HikvisionTreeDiagnostic $stream 2 $tree2Offset $tree2Size $capacity $videoOffset $blockSize $blockCount
			$report.Trees = @($tree1, $tree2)
			Set-DiagnosticStage 'primary-deep-scan'
			$deep1 = Get-HikDeepTree $stream $tree1Offset $tree1Size $capacity $videoOffset $blockSize $blockCount
			Set-DiagnosticStage 'backup-deep-scan'
			$deep2 = Get-HikDeepTree $stream $tree2Offset $tree2Size $capacity $videoOffset $blockSize $blockCount
			$report.DeepInspection = @($deep1, $deep2)
			Set-DiagnosticStage 'index-summary'
			for ($copy = 0; $copy -lt 2; $copy++) {
				$detail = $report.DeepInspection[$copy]
				$tree = $report.Trees[$copy]
				$leafRows = @($detail.Pages | Where-Object { $_.ReadOK -and $_.RoleHint -eq 'leaf-candidate' })
				$records = [UInt64] 0
				foreach ($row in $leafRows) { $records += $row.DeclaredCountAt10 }
				$summary = [ordered]@{
					LeafCandidatePages = $leafRows.Count
					LeafCandidateRecords = $records
					RecordCountMatchesBlockCount = ($records -eq $blockCount)
					CountsArePartial = $detail.Truncated
					FooterTarget = $null
				}
				if ($tree.PSObject.Properties['FooterValueAt18']) {
					$value = [Convert]::ToUInt64($tree.FooterValueAt18.Substring(2), 16)
					$base = [Convert]::ToUInt64($detail.Offset.Substring(2), 16)
					if ($value -ge $base) {
						$relative = Format-HikOffset ($value - $base)
						$target = @($detail.Pages | Where-Object { $_.RelativeOffset -eq $relative })
						if ($target.Count -eq 1 -and $target[0].ReadOK) {
							$summary.FooterTarget = [ordered]@{
								RelativeOffset = $relative; RoleHint = $target[0].RoleHint
								DeclaredCountAt10 = $target[0].DeclaredCountAt10; NextAt20 = $target[0].NextAt20
							}
						}
					}
				}
				if ($tree.PSObject.Properties['LeafChain']) {
					$visited = @{}
					foreach ($row in $tree.LeafChain.Pages) { $visited[$row.RelativeOffset] = $true }
					$summary.LeafCandidatesOutsideWalk = @($leafRows | Where-Object { -not $visited.ContainsKey($_.RelativeOffset) } | ForEach-Object { $_.RelativeOffset })
				}
				$detail | Add-Member -NotePropertyName Summary -NotePropertyValue $summary
			}
			Set-DiagnosticStage 'video-headers'
			$probes = New-Object 'System.Collections.Generic.List[object]'
			$sampled = @{}
			foreach ($candidate in $videoCandidates) {
				$sampled[$candidate.ToString()] = $true
				$probes.Add((Get-HikMediaHint $stream $candidate $blockSize 'leaf-layout-candidate'))
			}
			# Fill remaining budget with reproducible geometry samples spread over the disk.
			for ($k = 0; $k -lt $MaxVideoProbes -and $probes.Count -lt $MaxVideoProbes; $k++) {
				$index = if ($MaxVideoProbes -eq 1) { 0 } else { [Math]::Floor([decimal] $k * ($blockCount - 1) / ($MaxVideoProbes - 1)) }
				$candidate = $videoOffset + [UInt64] ([decimal] $index * $blockSize)
				if (-not $sampled.ContainsKey($candidate.ToString())) {
					$sampled[$candidate.ToString()] = $true
					$probes.Add((Get-HikMediaHint $stream $candidate $blockSize 'geometry-sample'))
				}
			}
			$report.VideoHeaders = @($probes.ToArray())
			$report.Privacy.VideoPayloadProbed = ($script:videoProbeAttempts -gt 0)
			$report.MetadataChecksPassed = $tree1.Recognized -or $tree2.Recognized
			if (-not $report.MetadataChecksPassed -and ($null -eq $tree1.Recognized -or $null -eq $tree2.Recognized)) {
				$report.MetadataChecksPassed = $null
			}
		}
	}

	Set-DiagnosticStage 'report-output'
	$totalWatch.Stop()
	$report.Timing = [ordered]@{
		DiagnosticMilliseconds = [Math]::Round($totalWatch.Elapsed.TotalMilliseconds, 3)
		ReadMilliseconds = [Math]::Round($script:readMilliseconds, 3)
		SlowReadThresholdMilliseconds = $SlowReadThresholdMilliseconds
		SlowReadCount = $script:slowReadCount
		FailedReadCount = $script:failedReadCount
		Stages = @($script:stages.ToArray())
		SlowestReads = @($script:slowestReads)
		ReadFailures = @($script:readFailures.ToArray())
		ReadFailuresTruncated = ($script:failedReadCount -gt 32)
		Notice = 'Stage times include parsing and progress overhead. SlowestReads is capped at 32. Offsets are filesystem-relative; AlignedSourceOffset includes BaseOffset. No forced device timeout. JSON serialization/output is excluded.'
	}
	$report.ReadStatistics = [ordered]@{ AttemptedReads = $script:readCalls; RequestedAlignedBytes = $script:readBytes; VideoProbeAttempts = $script:videoProbeAttempts }
	$json = $report | ConvertTo-Json -Depth 12
	if ([string]::IsNullOrWhiteSpace($OutputPath)) {
		$json
	}
	else {
		$fullOutputPath = [IO.Path]::GetFullPath($OutputPath)
		$outputDirectory = Split-Path -Parent $fullOutputPath
		if (-not [string]::IsNullOrEmpty($outputDirectory)) {
			[IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
		}
		$utf8WithoutBom = [Text.UTF8Encoding]::new($false)
		$outputStream = [IO.File]::Open($fullOutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
		try {
			$encoded = $utf8WithoutBom.GetBytes($json + [Environment]::NewLine)
			$outputStream.Write($encoded, 0, $encoded.Length)
		}
		finally { $outputStream.Dispose() }
		Write-Host ('Diagnostic report written to {0}' -f $fullOutputPath)
		Write-Host 'Only diagnostic fields were exported. Review the report before sharing.'
	}
}
finally {
	Write-Progress -Activity 'Hikvision diagnostic' -Completed
	if ($null -ne $stream) {
		$stream.Dispose()
	}
}
