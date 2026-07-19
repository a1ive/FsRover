#Requires -Version 5.1

<#
.SYNOPSIS
Generate a preview page for icon resource IDs in a Windows PE resource file.

.DESCRIPTION
Enumerate numeric RT_GROUP_ICON resources in a DLL, EXE, CPL, OCX, or MUN
file and extract each icon with SHDefExtractIconW(resource ID). The generated
HTML can filter IDs, resize icons, and copy an ID on click.

.PARAMETER ResourcePath
The PE resource file to inspect. The default is System32\SHELL32.dll for this
Windows installation. DllPath is retained as an alias.

.PARAMETER IconSize
The extraction size in pixels. The default is 48.

.PARAMETER OutputPath
The generated HTML path. The default is in the temporary directory.

.PARAMETER NoOpen
Generate the HTML without opening it in the default browser.

.EXAMPLE
.\scripts\Preview-ResourceIcons.ps1

.EXAMPLE
.\scripts\Preview-ResourceIcons.ps1 C:\Windows\System32\imageres.dll

.EXAMPLE
.\scripts\Preview-ResourceIcons.ps1 -ResourcePath .\FsRover.exe -IconSize 64 -NoOpen
#>

[CmdletBinding()]
param (
	[Parameter(Position = 0)]
	[Alias('DllPath')]
	[string] $ResourcePath = (Join-Path $env:SystemRoot 'System32\SHELL32.dll'),

	[Parameter()]
	[ValidateRange(16, 256)]
	[int] $IconSize = 48,

	[Parameter()]
	[string] $OutputPath,

	[Parameter()]
	[switch] $NoOpen
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ResourcePath -PathType Leaf)) {
	throw "Resource file not found: $ResourcePath"
}

$ResourcePath = (Resolve-Path -LiteralPath $ResourcePath).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
	$outputName = ([System.IO.Path]::GetFileName($ResourcePath) -replace '[^A-Za-z0-9._-]', '_') + '-icons.html'
	$OutputPath = Join-Path ([System.IO.Path]::GetTempPath()) $outputName
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrEmpty($outputDirectory)) {
	[System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}

Add-Type -AssemblyName System.Drawing

if (-not ('ResourceIconViewer.NativeMethods' -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace ResourceIconViewer
{
    public static class NativeMethods
    {
        private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        private const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
        private const int ERROR_RESOURCE_TYPE_NOT_FOUND = 1813;
        private static readonly IntPtr RT_GROUP_ICON = new IntPtr(14);

        private delegate bool EnumResNameProc(
            IntPtr module, IntPtr type, IntPtr name, IntPtr parameter);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryExW(
            string fileName, IntPtr file, uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumResourceNamesW(
            IntPtr module, IntPtr type, EnumResNameProc callback, IntPtr parameter);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
        private static extern int SHDefExtractIconW(
            string iconFile, int iconIndex, uint flags,
            out IntPtr largeIcon, IntPtr smallIcon, uint iconSize);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyIcon(IntPtr icon);

        public static int[] GetNumericIconIds(string fileName)
        {
            IntPtr module = LoadLibraryExW(
                fileName, IntPtr.Zero,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (module == IntPtr.Zero)
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(), "Unable to load resources from " + fileName);

            try
            {
                List<int> ids = new List<int>();
                EnumResNameProc callback = delegate(
                    IntPtr unusedModule, IntPtr unusedType,
                    IntPtr name, IntPtr unusedParameter)
                {
                    ulong value = unchecked((ulong)name.ToInt64());
                    if ((value >> 16) == 0)
                        ids.Add((int)(value & 0xffff));
                    return true;
                };

                if (!EnumResourceNamesW(module, RT_GROUP_ICON, callback, IntPtr.Zero))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error != ERROR_RESOURCE_TYPE_NOT_FOUND)
                        throw new System.ComponentModel.Win32Exception(
                            error, "Unable to enumerate icon resources");
                }

                ids.Sort();
                return ids.ToArray();
            }
            finally
            {
                FreeLibrary(module);
            }
        }

        public static IntPtr ExtractIcon(string fileName, int resourceId, int size)
        {
            IntPtr icon;
            int result = SHDefExtractIconW(
                fileName, -resourceId, 0, out icon, IntPtr.Zero, (uint)size);
            return result == 0 ? icon : IntPtr.Zero;
        }
    }
}
'@
}

function Convert-IconToDataUri {
	param (
		[Parameter(Mandatory)]
		[string] $Path,

		[Parameter(Mandatory)]
		[int] $ResourceId,

		[Parameter(Mandatory)]
		[int] $Size
	)

	$handle = [ResourceIconViewer.NativeMethods]::ExtractIcon($Path, $ResourceId, $Size)
	if ($handle -eq [IntPtr]::Zero) {
		return $null
	}

	$icon = $null
	$bitmap = $null
	$stream = $null
	try {
		$icon = [System.Drawing.Icon]::FromHandle($handle)
		$bitmap = $icon.ToBitmap()
		$stream = [System.IO.MemoryStream]::new()
		$bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
		return 'data:image/png;base64,' + [Convert]::ToBase64String($stream.ToArray())
	}
	finally {
		if ($null -ne $stream) {
			$stream.Dispose()
		}
		if ($null -ne $bitmap) {
			$bitmap.Dispose()
		}
		if ($null -ne $icon) {
			$icon.Dispose()
		}
		[void] [ResourceIconViewer.NativeMethods]::DestroyIcon($handle)
	}
}

$resourceIds = [ResourceIconViewer.NativeMethods]::GetNumericIconIds($ResourcePath)
if ($resourceIds.Count -eq 0) {
	throw "No numeric RT_GROUP_ICON resources found in: $ResourcePath"
}
$cards = [System.Text.StringBuilder]::new()
$extractedCount = 0

foreach ($resourceId in $resourceIds) {
	$dataUri = Convert-IconToDataUri -Path $ResourcePath -ResourceId $resourceId -Size $IconSize
	if ($null -eq $dataUri) {
		[void] $cards.AppendLine(('<button class="card failed" data-id="{0}" title="Extraction failed"><span class="missing">?</span><code>{0}</code></button>' -f $resourceId))
		continue
	}

	$extractedCount++
	[void] $cards.AppendLine(('<button class="card" data-id="{0}" title="Click to copy ID {0}"><img src="{1}" alt="Resource ID {0}"><code>{0}</code></button>' -f $resourceId, $dataUri))
}

$resourceName = [System.IO.Path]::GetFileName($ResourcePath)
$encodedResourceName = [System.Net.WebUtility]::HtmlEncode($resourceName)
$encodedResourcePath = [System.Net.WebUtility]::HtmlEncode($ResourcePath)
$generatedAt = [System.Net.WebUtility]::HtmlEncode((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))
$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$encodedResourceName Icons by Resource ID</title>
<style>
:root { color-scheme: light dark; font-family: "Segoe UI", sans-serif; --icon-size: ${IconSize}px; }
* { box-sizing: border-box; }
body { margin: 0; background: Canvas; color: CanvasText; }
header { position: sticky; top: 0; z-index: 1; padding: 14px 18px; border-bottom: 1px solid GrayText; background: Canvas; }
h1 { margin: 0 0 8px; font-size: 18px; }
.meta { margin: 0 0 10px; color: GrayText; font-size: 12px; overflow-wrap: anywhere; }
.tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
input { width: 190px; padding: 6px 8px; font: inherit; }
.tools button { padding: 6px 10px; font: inherit; }
#status { min-width: 180px; color: GrayText; font-size: 12px; }
main { display: grid; grid-template-columns: repeat(auto-fill, minmax(92px, 1fr)); gap: 8px; padding: 12px; }
.card { min-height: 92px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 7px; border: 1px solid transparent; border-radius: 3px; background: transparent; color: inherit; cursor: pointer; }
.card:hover, .card:focus-visible { border-color: Highlight; background: color-mix(in srgb, Highlight 12%, transparent); outline: none; }
.card img { width: var(--icon-size); height: var(--icon-size); object-fit: contain; image-rendering: auto; }
.card code { font: 12px Consolas, monospace; }
.card.failed { opacity: .55; }
.missing { display: grid; place-items: center; width: var(--icon-size); height: var(--icon-size); border: 1px dashed GrayText; }
.hidden { display: none; }
</style>
</head>
<body>
<header>
	<h1>$encodedResourceName Icons by Resource ID</h1>
	<p class="meta">$encodedResourcePath | Extracted at ${IconSize}px | $generatedAt</p>
	<div class="tools">
		<input id="filter" type="search" inputmode="numeric" placeholder="Filter IDs, for example 16739" autofocus>
		<button type="button" data-size="24">24px</button>
		<button type="button" data-size="32">32px</button>
		<button type="button" data-size="48">48px</button>
		<button type="button" data-size="64">64px</button>
		<span id="status"></span>
	</div>
</header>
<main id="icons">
$cards</main>
<script>
const cards = [...document.querySelectorAll('.card')];
const filter = document.querySelector('#filter');
const status = document.querySelector('#status');
function update() {
	const query = filter.value.trim();
	let visible = 0;
	for (const card of cards) {
		const match = !query || card.dataset.id.includes(query);
		card.classList.toggle('hidden', !match);
		visible += Number(match);
	}
	status.textContent = 'Showing ' + visible + ' of ' + cards.length + ' resources; click to copy an ID';
}
filter.addEventListener('input', update);
document.querySelector('.tools').addEventListener('click', event => {
	const size = event.target.dataset.size;
	if (size) document.documentElement.style.setProperty('--icon-size', size + 'px');
});
async function copyText(value) {
	if (navigator.clipboard && window.isSecureContext) {
		await navigator.clipboard.writeText(value);
		return;
	}
	const input = document.createElement('textarea');
	input.value = value;
	input.style.position = 'fixed';
	input.style.opacity = '0';
	document.body.appendChild(input);
	input.select();
	const copied = document.execCommand('copy');
	input.remove();
	if (!copied) throw new Error('clipboard unavailable');
}
document.querySelector('#icons').addEventListener('click', async event => {
	const card = event.target.closest('.card');
	if (!card) return;
	try {
		await copyText(card.dataset.id);
		status.textContent = 'Copied resource ID ' + card.dataset.id;
	} catch {
		status.textContent = 'resource ID: ' + card.dataset.id;
	}
});
update();
</script>
</body>
</html>
"@

$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($OutputPath, $html, $utf8WithoutBom)

Write-Host "Generated $OutputPath ($extractedCount/$($resourceIds.Count) icons)."
if (-not $NoOpen) {
	Start-Process -FilePath $OutputPath
}
