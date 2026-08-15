param(
    [string]$BuildDirectory = "build/windows-wasm-test"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildPath = Join-Path $RepositoryRoot $BuildDirectory
$DllPath = Join-Path $BuildPath "hello-go.dll"
$WasmPath = Join-Path $RepositoryRoot "dist/fritter.wasm"
$LoaderCount = 8

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

    for ($Attempt = 1; $Attempt -le $LoaderCount; $Attempt++) {
        $AttemptLabel = $Attempt.ToString("D2")
        $BinPath = Join-Path $BuildPath "hello-go-$AttemptLabel.bin"
        $MarkerPath = Join-Path $BuildPath "hello-world-$PID-$AttemptLabel.txt"

        Write-Host "[$Attempt/$LoaderCount] Generating independently randomized loader: $BinPath"
        go run ./cmd/fritter-gen -wasm $WasmPath -input $DllPath -method HelloWorld -output $BinPath
        $GenerationExitCode = $LASTEXITCODE
        if ($GenerationExitCode -ne 0) {
            throw "loader $Attempt/$LoaderCount generation failed with exit code $GenerationExitCode (output: $BinPath)"
        }

        if (-not (Test-Path $BinPath -PathType Leaf) -or (Get-Item $BinPath).Length -eq 0) {
            throw "loader $Attempt/$LoaderCount did not produce a non-empty artifact (output: $BinPath)"
        }

        $env:FRITTER_HELLO_PATH = $MarkerPath
        go run ./cmd/run-shellcode -input $BinPath -timeout 45s
        $ExecutionExitCode = $LASTEXITCODE
        if ($ExecutionExitCode -ne 0) {
            throw "loader $Attempt/$LoaderCount execution failed with exit code $ExecutionExitCode (input: $BinPath; marker: $MarkerPath)"
        }

        if (-not (Test-Path $MarkerPath -PathType Leaf)) {
            throw "loader $Attempt/$LoaderCount did not create its hello-world marker (input: $BinPath; marker: $MarkerPath)"
        }

        $MarkerContent = Get-Content -Raw $MarkerPath
        if ($MarkerContent.Trim() -ne "hello world from Go DLL") {
            throw "loader $Attempt/$LoaderCount wrote unexpected marker content (marker: $MarkerPath): $MarkerContent"
        }

        Write-Host "[$Attempt/$LoaderCount] Loader passed: $BinPath"
    }

    Write-Host "Windows WASM integration test passed for $LoaderCount independently generated loaders"
}
finally {
    Pop-Location
}
