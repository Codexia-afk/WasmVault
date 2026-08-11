#!/bin/bash
set -e

source "$HOME/.cargo/env" 2>/dev/null || true

PLUGINS_DIR="plugins"
OUTPUT_DIR="target/wasm_plugins"

mkdir -p "$OUTPUT_DIR"

echo "Building demo plugins to target wasm32-wasip1..."

for plugin_dir in "$PLUGINS_DIR"/*; do
  if [ -d "$plugin_dir" ]; then
    plugin_name=$(basename "$plugin_dir")
    echo "Compiling $plugin_name..."
    rustc --target wasm32-wasip1 -O "$plugin_dir/src/main.rs" -o "$OUTPUT_DIR/$plugin_name.wasm"
    cp "$plugin_dir/plugin.toml" "$OUTPUT_DIR/$plugin_name.toml"
  fi
done

echo "Successfully built all plugins into $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"
