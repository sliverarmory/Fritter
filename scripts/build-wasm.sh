#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATED_DIR="${ROOT_DIR}/generated"
DIST_DIR="${ROOT_DIR}/dist"
EMCC="${EMCC:-emcc}"
EMSCRIPTEN_PREFIX="${EMSCRIPTEN_PREFIX:-}"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    exit 1
  fi
}

require_tool "${EMCC}"

if [[ -z "${EMSCRIPTEN_PREFIX}" ]] && command -v brew >/dev/null 2>&1; then
  EMSCRIPTEN_PREFIX="$(brew --prefix emscripten 2>/dev/null || true)"
fi

if [[ -n "${EMSCRIPTEN_PREFIX}" ]]; then
  if [[ -x /opt/homebrew/bin/python3 ]]; then
    export EMSDK_PYTHON=/opt/homebrew/bin/python3
  elif command -v python3 >/dev/null 2>&1; then
    export EMSDK_PYTHON="$(command -v python3)"
  fi

  export EM_CONFIG="${EM_CONFIG:-${ROOT_DIR}/build/emscripten.config}"
  export EM_CACHE="${EM_CACHE:-${ROOT_DIR}/build/emscripten-cache}"
  mkdir -p "$(dirname "${EM_CONFIG}")"
  mkdir -p "${EM_CACHE}"

  if [[ ! -f "${EM_CONFIG}" ]]; then
    cat > "${EM_CONFIG}" <<EOF
import os

LLVM_ROOT = os.path.expanduser('${EMSCRIPTEN_PREFIX}/libexec/llvm/bin')
BINARYEN_ROOT = os.path.expanduser('${EMSCRIPTEN_PREFIX}/libexec/binaryen')
EMSCRIPTEN_ROOT = os.path.expanduser('${EMSCRIPTEN_PREFIX}/libexec')
NODE_JS = os.path.expanduser('$(command -v node)')
JAVA = 'java'
EOF
  fi
fi

for config in poly_seed.h api_shuffle.h; do
  if [[ ! -f "${ROOT_DIR}/include/${config}" ]]; then
    echo "missing ${ROOT_DIR}/include/${config}" >&2
    echo "run scripts/build-loader-blobs.sh first" >&2
    exit 1
  fi
done

for header in \
  loader_peb1_exe_x64.h \
  loader_peb1_fn_table_x64.h \
  loader_peb1_ref_table_x64.h \
  loader_peb2_exe_x64.h \
  loader_peb2_fn_table_x64.h \
  loader_peb2_ref_table_x64.h \
  dispatch_shim_exe_x64.h; do
  if [[ ! -f "${GENERATED_DIR}/${header}" ]]; then
    echo "missing ${GENERATED_DIR}/${header}" >&2
    echo "run scripts/build-loader-blobs.sh first" >&2
    exit 1
  fi
done

mkdir -p "${DIST_DIR}"

"${EMCC}" \
  -O2 \
  -fpack-struct=8 \
  -DFRITTER_WASM_BUILD \
  -DFRITTER_NO_APLIB \
  -I "${ROOT_DIR}/include" \
  -I "${GENERATED_DIR}" \
  --no-entry \
  -sSTANDALONE_WASM \
  -sPURE_WASI \
  -sWASMFS \
  -sEXPORTED_FUNCTIONS='["_malloc","_free","_fritter_wasm_generate","_fritter_wasm_write_file","_fritter_wasm_file_size","_fritter_wasm_read_file"]' \
  -sINITIAL_MEMORY=67108864 \
  "${ROOT_DIR}/fritter.c" \
  "${ROOT_DIR}/hash.c" \
  "${ROOT_DIR}/encrypt.c" \
  "${ROOT_DIR}/format.c" \
  "${ROOT_DIR}/loader/clib.c" \
  -o "${DIST_DIR}/fritter.wasm"

echo "built ${DIST_DIR}/fritter.wasm"
