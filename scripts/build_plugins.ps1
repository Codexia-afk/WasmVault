$ErrorActionPreference = "Stop"

$PluginsDir = "plugins"
$OutputDir = "target/wasm_plugins"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

Write-Host "Building demo plugins to target wasm32-wasip1..."

Get-ChildItem -Path $PluginsDir -Directory | ForEach-Object {
    $pluginName = $_.Name
    $pluginSrc = Join-Path $_.FullName "src/main.rs"
    $pluginToml = Join-Path $_.FullName "plugin.toml"
    $outWasm = Join-Path $OutputDir "$pluginName.wasm"
    $outToml = Join-Path $OutputDir "$pluginName.toml"

    if (Test-Path $pluginSrc) {
        Write-Host "Compiling $pluginName..."
        rustc --target wasm32-wasip1 -O $pluginSrc -o $outWasm
        Copy-Item -Path $pluginToml -Destination $outToml -Force
    }
}

Write-Host "Successfully built all plugins into $OutputDir/"
Get-ChildItem -Path $OutputDir
