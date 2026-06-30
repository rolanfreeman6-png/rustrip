# Build a small Rust binary that can serve as a richer fixture for rustrip.
# Run from a parent directory containing this directory. Output:
#   tests/fixtures/dist/sample-stripped.exe (or .elf on Linux)

# Resolve to absolute path regardless of where invoked from.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fixture = Join-Path $here "..\tests\fixtures"
$dist = Join-Path $fixture "dist"
New-Item -ItemType Directory -Path $dist -Force | Out-Null

# Locate cargo.
$cargo = (Get-Command cargo.exe -ErrorAction SilentlyContinue).Source
if (-not $cargo) {
    $cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
}
if (-not (Test-Path -LiteralPath $cargo)) {
    Write-Error "cargo not found at $cargo. Install rustup or update PATH."
    exit 2
}

# Build release. We rely on `[profile.release] strip = "symbols"` from the
# root Cargo.toml so stripping is handled by rustc/Cargo automatically when
# supported by the host toolchain.
& $cargo build --release --manifest-path (Join-Path $fixture "Cargo.toml")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$built = Get-ChildItem -Path (Join-Path $fixture "target\release") -Filter "sample*" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $built) {
    Write-Error "Built binary not found in target\release. Aborting."
    exit 3
}

Copy-Item -LiteralPath $built.FullName -Destination (Join-Path $dist $built.Name) -Force
Write-Host "fixture built at: $($built.FullName)"
