param(
    [Parameter(Mandatory = $true)][string]$InputLib,
    [Parameter(Mandatory = $true)][string]$OutputLib
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Rust can bundle identical Windows import objects twice. Preserve object bytes
# (including LLVM/LTO data) and relocate both COFF linker indexes after deduping.
function Get-U32([byte[]]$Data, [int]$Offset, [bool]$BigEndian = $false) {
    $Word = [byte[]]$Data[$Offset..($Offset + 3)]
    if ($BigEndian) { [Array]::Reverse($Word) }
    return [BitConverter]::ToUInt32($Word, 0)
}
function Set-U32([byte[]]$Data, [int]$Offset, [uint32]$Value, [bool]$BigEndian = $false) {
    $Word = [BitConverter]::GetBytes($Value)
    if ($BigEndian) { [Array]::Reverse($Word) }
    [Array]::Copy($Word, 0, $Data, $Offset, 4)
}

$Members = [Collections.Generic.List[object]]::new()
$Canonical = @{}
$Seen = @{}
$LongNames = ''
$Reader = [IO.BinaryReader]::new([IO.File]::OpenRead($InputLib))
$Hash = [Security.Cryptography.SHA256]::Create()
try {
    if ([Text.Encoding]::ASCII.GetString($Reader.ReadBytes(8)) -ne "!<arch>`n") { throw 'Invalid COFF archive magic' }
    while ($Reader.BaseStream.Position -lt $Reader.BaseStream.Length) {
        $Offset = $Reader.BaseStream.Position
        $Header = $Reader.ReadBytes(60)
        if ($Header.Length -ne 60 -or $Header[58] -ne 0x60 -or $Header[59] -ne 0x0a) { throw 'Invalid COFF member header' }
        $Name = [Text.Encoding]::ASCII.GetString($Header, 0, 16).Trim()
        $Size = [int]::Parse([Text.Encoding]::ASCII.GetString($Header, 48, 10).Trim())
        if ($Size -lt 0 -or $Size -gt ($Reader.BaseStream.Length - $Reader.BaseStream.Position)) { throw 'Invalid COFF member size' }
        $Data = $Reader.ReadBytes($Size)
        if ($Size % 2) { [void]$Reader.ReadByte() }
        $Duplicate = $false
        $Canonical[$Offset] = $Offset
        if ($Name -eq '//') {
            $LongNames = [Text.Encoding]::ASCII.GetString($Data)
        } elseif ($Name -ne '/') {
            $ResolvedName = $Name
            if ($Name -match '^/(\d+)$') { $ResolvedName = ($LongNames.Substring([int]$Matches[1]) -split "`0|/`n", 2)[0] }
            $Key = $ResolvedName + '|' + [BitConverter]::ToString($Hash.ComputeHash($Data))
            if ($Seen.ContainsKey($Key)) {
                $Duplicate = $true
                $Canonical[$Offset] = $Seen[$Key]
            } else { $Seen[$Key] = $Offset }
        }
        $Members.Add([PSCustomObject]@{ Offset = $Offset; Header = $Header; Name = $Name; Data = $Data; Duplicate = $Duplicate })
    }
} finally {
    $Reader.Dispose()
    $Hash.Dispose()
}
$Indexes = @($Members | Where-Object { $_.Name -eq '/' })
if ($Indexes.Count -ne 2) { throw 'Expected both MSVC COFF linker indexes' }

# The second index uses a member-offset array and one-based uint16 symbol indices.
$Second = $Indexes[1].Data
$OldCount = Get-U32 $Second 0
$UniqueOffsets = [Collections.Generic.List[long]]::new()
$IndexByOffset = @{}
$NewIndex = @{}
for ($i = 0; $i -lt $OldCount; $i++) {
    $OldOffset = [long](Get-U32 $Second (4 + 4 * $i))
    $KeptOffset = $Canonical[$OldOffset]
    if ($null -eq $KeptOffset) { throw 'Invalid member offset in COFF index' }
    if (-not $IndexByOffset.ContainsKey($KeptOffset)) {
        $UniqueOffsets.Add($KeptOffset)
        $IndexByOffset[$KeptOffset] = $UniqueOffsets.Count
    }
    $NewIndex[$i + 1] = $IndexByOffset[$KeptOffset]
}
$TailOffset = 4 + 4 * $OldCount
$NewSecond = [byte[]]::new(4 + 4 * $UniqueOffsets.Count + $Second.Length - $TailOffset)
Set-U32 $NewSecond 0 $UniqueOffsets.Count
[Array]::Copy($Second, $TailOffset, $NewSecond, (4 + 4 * $UniqueOffsets.Count), ($Second.Length - $TailOffset))
$SymbolCount = Get-U32 $NewSecond (4 + 4 * $UniqueOffsets.Count)
for ($i = 0; $i -lt $SymbolCount; $i++) {
    $Position = 8 + 4 * $UniqueOffsets.Count + 2 * $i
    $OldIndex = [int][BitConverter]::ToUInt16($NewSecond, $Position)
    $Word = [BitConverter]::GetBytes([uint16]$NewIndex[$OldIndex])
    [Array]::Copy($Word, 0, $NewSecond, $Position, 2)
}
$Indexes[1].Data = $NewSecond

$NewOffsets = @{}
$NextOffset = 8L
foreach ($Member in $Members) {
    if ($Member.Duplicate) { continue }
    $NewOffsets[$Member.Offset] = $NextOffset
    $NextOffset += 60 + $Member.Data.Length + ($Member.Data.Length % 2)
}
for ($i = 0; $i -lt $UniqueOffsets.Count; $i++) {
    Set-U32 $NewSecond (4 + 4 * $i) $NewOffsets[$UniqueOffsets[$i]]
}
# The first index stores direct member offsets in big endian order.
$First = $Indexes[0].Data
$FirstSymbolCount = Get-U32 $First 0 $true
for ($i = 0; $i -lt $FirstSymbolCount; $i++) {
    $Position = 4 + 4 * $i
    $OldOffset = [long](Get-U32 $First $Position $true)
    Set-U32 $First $Position $NewOffsets[$Canonical[$OldOffset]] $true
}
$Writer = [IO.BinaryWriter]::new([IO.File]::Create($OutputLib))
try {
    $Writer.Write([Text.Encoding]::ASCII.GetBytes("!<arch>`n"))
    foreach ($Member in $Members) {
        if ($Member.Duplicate) { continue }
        $SizeField = [Text.Encoding]::ASCII.GetBytes($Member.Data.Length.ToString().PadRight(10))
        [Array]::Copy($SizeField, 0, $Member.Header, 48, 10)
        $Writer.Write([byte[]]$Member.Header)
        $Writer.Write([byte[]]$Member.Data)
        if ($Member.Data.Length % 2) { $Writer.Write([byte]0x0a) }
    }
} finally { $Writer.Dispose() }
