param(
    [string]$BuildDirectory = "build/windows-wasm-test"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildPath = Join-Path $RepositoryRoot $BuildDirectory
$DllPath = Join-Path $BuildPath "hello-go.dll"
$BinPath = Join-Path $BuildPath "hello-go.bin"
$MarkerPath = Join-Path $BuildPath "hello-world-$PID.txt"
$WasmPath = Join-Path $RepositoryRoot "dist/fritter.wasm"

if (-not (Test-Path $WasmPath -PathType Leaf)) {
    throw "missing Fritter WASM module: $WasmPath"
}

New-Item -ItemType Directory -Force -Path $BuildPath | Out-Null

Push-Location $RepositoryRoot
try {
    $env:CGO_ENABLED = "1"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"

    go build -buildmode=c-shared -o $DllPath ./examples/go-dll-hello
    if ($LASTEXITCODE -ne 0) {
        throw "failed to build the Go DLL"
    }

    go run ./cmd/fritter-gen -wasm $WasmPath -input $DllPath -method HelloWorld -output $BinPath
    if ($LASTEXITCODE -ne 0) {
        throw "failed to generate shellcode with Fritter WASM"
    }

    if (-not (Test-Path $BinPath -PathType Leaf) -or (Get-Item $BinPath).Length -eq 0) {
        throw "Fritter did not produce a non-empty .bin file"
    }

    $env:FRITTER_HELLO_PATH = $MarkerPath
    go run ./cmd/run-shellcode -input $BinPath -timeout 45s
    if ($LASTEXITCODE -ne 0) {
        throw "generated shellcode execution failed"
    }

    if (-not (Test-Path $MarkerPath -PathType Leaf)) {
        throw "the Go DLL did not create its hello-world marker"
    }

    $MarkerContent = Get-Content -Raw $MarkerPath
    if ($MarkerContent.Trim() -ne "hello world from Go DLL") {
        throw "unexpected hello-world marker content: $MarkerContent"
    }

    Write-Host "Windows WASM integration test passed: $BinPath"
}
finally {
    Pop-Location
}
