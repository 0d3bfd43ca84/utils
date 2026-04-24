#Requires -Version 7.0
<#
.SYNOPSIS
    Genera passwords criptograficamente seguras (CSPRNG).

.DESCRIPTION
    Garantias de composicion:
      - Longitud   : configurable (default 24, min 16, max 39)
      - Composicion: minimo configurable por grupo (default 4)
      - Entropia   : 148.1 bits a longitud 24 (log2(72^24)) — NIST SP 800-63B AAL3
      - Sin ambiguos visuales (0/O, 1/l/I)
      - Sin caracteres problematicos en JSON o Basic Auth
      - Mezcla Fisher-Yates con CSPRNG

.PARAMETER Count
    Numero de passwords a generar. Default: 1. Maximo: 100.

.PARAMETER Length
    Longitud de cada password. Default: 24. Rango: 16-39.
    El limite superior de 39 corresponde al hard limit del firmware iLO HPE.

.PARAMETER MinEach
    Minimo de caracteres por grupo (mayus/minus/digitos/simbolos).
    Default: 4. Debe cumplir: MinEach * 4 <= Length.

.EXAMPLE
    .\SecurePassword.ps1
    Genera 1 password de 24 caracteres.

.EXAMPLE
    .\SecurePassword.ps1 5
    Genera 5 passwords de 24 caracteres.

.EXAMPLE
    .\SecurePassword.ps1 -Count 3 -Length 32 -MinEach 6
    Genera 3 passwords de 32 caracteres con minimo 6 de cada tipo.
#>

param(
    [ValidateRange(1, 100)]
    [int] $Count   = 1,

    [ValidateRange(16, 39)]
    [int] $Length  = 24,

    [ValidateRange(1, 9)]
    [int] $MinEach = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Validacion cruzada — MinEach * 4 grupos no puede superar Length
if ($MinEach * 4 -gt $Length) {
    Write-Error "MinEach ($MinEach) * 4 grupos = $($MinEach*4) supera Length ($Length). Reduce MinEach o aumenta Length."
    exit 1
}

# =====================================================================
# CHARSET
# =====================================================================

# Sin ambiguos visuales (0/O, 1/l/I) ni chars problematicos en JSON/Basic Auth
$upper   = 'ABCDEFGHJKMNPQRSTUVWXYZ'.ToCharArray()   # sin I, O
$lower   = 'abcdefghjkmnpqrstuvwxyz'.ToCharArray()   # sin i, l, o
$digits  = '23456789'.ToCharArray()                   # sin 0, 1
$symbols = '!@#$*()-_=+[];:,.?'.ToCharArray()         # sin " ' ` \ < > % ^ ~ espacio

$charset = $upper + $lower + $digits + $symbols

# =====================================================================
# CSPRNG — buffer compartido, una sola instancia para toda la ejecucion
# =====================================================================

$rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = [byte[]]::new(4)

function Get-CryptoRandom ([int]$Max) {
    # Entero criptograficamente seguro en [0, Max) sin modulo bias
    $limit = [uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$Max)
    do {
        $rng.GetBytes($bytes)
        $val = [System.BitConverter]::ToUInt32($bytes, 0)
    } while ($val -ge $limit)
    return [int]($val % $Max)
}

# =====================================================================
# GENERADOR
# =====================================================================

function New-Password {
    $all = [System.Collections.Generic.List[char]]::new($Length)

    # Mandatory: MinEach chars de cada grupo
    for ($k = 0; $k -lt $MinEach; $k++) { $all.Add($upper[(Get-CryptoRandom $upper.Length)]) }
    for ($k = 0; $k -lt $MinEach; $k++) { $all.Add($lower[(Get-CryptoRandom $lower.Length)]) }
    for ($k = 0; $k -lt $MinEach; $k++) { $all.Add($digits[(Get-CryptoRandom $digits.Length)]) }
    for ($k = 0; $k -lt $MinEach; $k++) { $all.Add($symbols[(Get-CryptoRandom $symbols.Length)]) }

    # Fill: relleno hasta Length con charset completo
    while ($all.Count -lt $Length) {
        $all.Add($charset[(Get-CryptoRandom $charset.Length)])
    }

    # Fisher-Yates in-place con CSPRNG
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j       = Get-CryptoRandom ($i + 1)
        $tmp     = $all[$i]
        $all[$i] = $all[$j]
        $all[$j] = $tmp
    }

    # Construir string y limpiar lista inmediatamente
    $result = -join $all
    $all.Clear()
    return $result
}

# =====================================================================
# EJECUCION
# =====================================================================

# Detectar si hay consola interactiva para usar color
# Si no (pipeline, redireccion), usar Write-Output para compatibilidad
$interactive = $Host.UI.RawUI.WindowSize.Width -gt 0

try {
    for ($n = 0; $n -lt $Count; $n++) {
        $pwd = New-Password
        if ($interactive) {
            Write-Host $pwd -ForegroundColor Yellow
        } else {
            Write-Output $pwd
        }
        $pwd = $null
    }
}
finally {
    $rng.Dispose()
}