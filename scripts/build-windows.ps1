# SPDX-License-Identifier: GPL-2.0-or-later
param(
    [Parameter(Mandatory=$true)][string]$ToolsDir,
    [Parameter(Mandatory=$true)][string]$MakePath,
    [Parameter(Mandatory=$true)][string]$PythonHome,
    [string]$SourceRoot = (Join-Path $PSScriptRoot '../magiclantern'),
    [string]$BuildDate = (Get-Date -Format 'yyyy-MM-dd')
)
$ErrorActionPreference = 'Stop'
$tools = (Resolve-Path $ToolsDir).Path.Replace('\','/')
$source = (Resolve-Path $SourceRoot).Path
$make = (Resolve-Path $MakePath).Path
$pythonDir = (Resolve-Path $PythonHome).Path
$arm = "$tools/arm-gnu-toolchain-13.3.rel1-mingw-w64-i686-arm-none-eabi/bin"
foreach ($required in @("$tools/sh.exe", "$tools/python3.exe", "$arm/arm-none-eabi-gcc.exe")) {
    if (!(Test-Path -LiteralPath $required)) { throw "Missing tool: $required" }
}
$priorPath = $env:PATH
$priorPythonHome = $env:PYTHONHOME
$buildExit = 1
Push-Location (Join-Path $source 'platform/750D.110')
try {
    $env:PATH = "$tools;$arm;$pythonDir;$priorPath"
    $env:PYTHONHOME = $pythonDir
    & $make "SHELL=$tools/sh.exe" "ARM_BINPATH=$arm" PYTHON=python PYTHON3=python CONFIG_QEMU=y FATAL_WARNINGS=y "INCLUDE_ARGS=-I. -Iinclude -Ibuild-pc-full -I../../src" BUILD_DIR=build-pc-full "BUILD_DATE=$BuildDate" build-pc-full/autoexec -j4
    $buildExit = $LASTEXITCODE
} finally {
    $env:PATH = $priorPath
    $env:PYTHONHOME = $priorPythonHome
    Pop-Location
}
exit $buildExit
