#!/usr/bin/env pwsh

# ==============================
# Parámetros
# ==============================
#$version = "1.0"
#$appname = "Gradle"
#$branch = "1.0"
#$repositorio = "Gradle"

param (
    [Parameter(Mandatory=$true)]
    [string]$version,

    [Parameter(Mandatory=$true)]
    [string]$appname

)

$branch = $version
$repositorio = $appname

# ==============================
# Configuración de errores
# ==============================
$ErrorActionPreference = "Stop"
Set-PSDebug -Trace 1

# ==============================
# Configurar JAVA_HOME temporal a JDK 17
# ==============================
$env:JAVA_HOME = "C:\Program Files\Java\jdk-17"
$env:PATH = "$($env:JAVA_HOME)\bin;$($env:PATH)"
$env:SCANCENTRAL_JAVA_HOME = "C:\Program Files\Java\jdk-17"

Write-Host "Usando JAVA_HOME=$env:JAVA_HOME"
java -version

# Listar certificados Fortify (si existen)
try {
    keytool -list -v -keystore "$env:JAVA_HOME/lib/security/cacerts" -storepass changeit |
        Select-String "fortify"
} catch {
    # Ignorar errores
}


$ssc_url = "https://ssc.otlatam.com/ssc"
$ssctoken = "6a28a13a-0575-4409-a385-231fb1a1149e"
$debrickedtoken = "e20bebc6fdf1b7b1074f52e3f7283d98011a678183664b9d"
$author = "admin"
$integration = "CLI"
$debricked_bin = "C:\Users\Administrator\Downloads\debricked.exe"
$fcli_path = "C:\Users\Administrator\Downloads"

# ==============================
# Primera parte: Escaneo Debricked
# ==============================
Write-Host "=== Iniciando escaneo con Debricked ==="

$SCAN_OUTPUT = & $debricked_bin scan `
    -t $debrickedtoken `
    -i $integration `
    -r $repositorio `
    -b $branch `
    --generate-commit-name `
    -a $author 2>&1

$EXIT_CODE = $LASTEXITCODE
$SCAN_OUTPUT | ForEach-Object { Write-Host $_ }

if ($EXIT_CODE -ne 0) {
    Write-Host "? El escaneo falló con exit code $EXIT_CODE."
}

if ($SCAN_OUTPUT -match "Gradle wasn't found") {
    Write-Host "?? Falta Gradle en el PATH"
}
if ($SCAN_OUTPUT -match "non-enterprise customer trying to upload fingerprints") {
    Write-Host "? Uso de fingerprints sin cuenta Enterprise"
}
if ($SCAN_OUTPUT -match "Could not validate enterprise billing plan") {
    Write-Host "?? No se pudo validar el plan Enterprise"
}
if ($SCAN_OUTPUT -match "failed to find repository URL") {
    Write-Host "?? No se detectó URL del repo"
}

$match = [regex]::Match(($SCAN_OUTPUT -join "`n"), '([0-9]+)\s+vulnerabilities found')

if ($match.Success) {
    $VULNS = [int]$match.Groups[1].Value

    if ($VULNS -gt 0) {
        Write-Host "?? Escaneo completado con $VULNS vulnerabilidades encontradas."
    } else {
        Write-Host "? Escaneo exitoso, sin vulnerabilidades."
    }
} else {
    Write-Host "?? No se pudo determinar si hubo vulnerabilidades."
}

# ==============================
# Segunda parte: Carga a SSC
# ==============================
Write-Host "?? Iniciando carga de reporte Debricked a SSC"
Write-Host "App: $appname | Versión: $version | Rama: $branch | Repo: $repositorio"

$session_output = java -jar "$fcli_path\fcli.jar" `
    ssc session login `
    --url $ssc_url `
    -t $ssctoken 2>&1
	
$session_text = $session_output -join "`n"

if ($session_text -notmatch "\bCREATED\b") {
    Write-Host "? Error al iniciar sesión en SSC"
    Write-Host $session_text
    exit 1
}

Write-Host "? Sesión iniciada correctamente en SSC"

# --- Validar o crear appVersion ---
Write-Host "?? Validando appVersion ${appname}:${version}"

$appversion_exists = $true
$appversion_output = ""

try {
    $appversion_output = & java -jar "$fcli_path\fcli.jar" `
        ssc appversion get "${appname}:${version}" 2>&1

}
catch {
    $appversion_exists = $false
}

if (-not $appversion_exists) {

    Write-Host "?? La appVersion no existe, creando ${appname}:${version}"

    $appversion_create = & java -jar "$fcli_path\fcli.jar" `
        ssc appversion create "${appname}:${version}" `
        --auto-required-attrs `
        --issue-template "Prioritized High Risk Issue Template" 2>&1 | Out-String

Write-Host $appversion_create

$appversion_id = (
    $appversion_create -split "`r?`n" |
    ForEach-Object {
        if ($_ -match '([0-9]+)') {
            $matches[1]
        }
    } |
    Select-Object -First 1
)

if (-not $appversion_id) {
    throw "? No se pudo obtener el ID de la appVersion"
}

Write-Host "? AppVersion creada correctamente. ID: $appversion_id"

}
else {

Write-Host $appversion_output

$appversion_id = (
    $appversion_output |
    Where-Object { $_ -match '^\s*id:\s*\d+' } |
    Select-Object -First 1 |
    ForEach-Object { ($_ -split ':\s*')[1] }
)

    Write-Host "? AppVersion existente detectada. ID: $appversion_id"
}


# --- Importar resultados Debricked ---
$import_output = java -jar "$fcli_path\fcli.jar" `
    ssc artifact import-debricked `
    --appversion "${appname}:${version}" `
    --repository $repositorio `
    --branch $branch `
    --debricked-url "https://debricked.com" `
    --debricked-access-token $debrickedtoken 2>&1

Write-Host "===== IMPORT OUTPUT ====="
$import_output | ForEach-Object { Write-Host $_ }

Write-Host "========================="

$artifact_id = ($import_output |
    Select-String "^\s+(\d+)\s+" |
    ForEach-Object { $_.Matches[0].Groups[1].Value }
)

if (-not $artifact_id) {
    Write-Host "?? No se pudo obtener el ID del artefacto"
    java -jar "$fcli_path\fcli.jar" ssc session logout --no-revoke-token
    exit 1
}

Write-Host "? Artefacto importado correctamente. ID: $artifact_id"

# --- Esperar procesamiento ---
Write-Host "? Esperando procesamiento en SSC..."

java -jar "$fcli_path\fcli.jar" `
    ssc artifact wait-for $artifact_id `
    --timeout 5m `
    --interval 10s

if ($LASTEXITCODE -eq 0) {
    Write-Host "? Procesamiento completado"
} else {
    Write-Host "? Error durante el procesamiento del artefacto"
    exit 1
}

#java -jar "$fcli_path\fcli.jar" ssc action run gitlab-debricked-report --appversion $appversion_id --file debricked-report.json

#python debricked-convert-to-pdf.py

# --- Cerrar sesión ---
java -jar "$fcli_path\fcli.jar" ssc session logout --no-revoke-token
Write-Host "?? Sesión cerrada en SSC"

exit 0