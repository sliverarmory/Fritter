#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/loader-blobs"
GENERATED_DIR="${ROOT_DIR}/generated"
HOST_CC="${HOST_CC:-cc}"
MINGW_CC="${MINGW_CC:-x86_64-w64-mingw32-gcc}"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    exit 1
  fi
}

require_tool "${HOST_CC}"
require_tool "${MINGW_CC}"

mkdir -p "${BUILD_DIR}" "${GENERATED_DIR}"

"${HOST_CC}" \
  "${ROOT_DIR}/tools/gen_poly.c" \
  -o "${BUILD_DIR}/gen_poly"
"${BUILD_DIR}/gen_poly" "${ROOT_DIR}/include/poly_seed.h"

"${HOST_CC}" \
  "${ROOT_DIR}/tools/gen_api_shuffle.c" \
  -o "${BUILD_DIR}/gen_api_shuffle"
"${BUILD_DIR}/gen_api_shuffle" \
  "${ROOT_DIR}/include/api_master.h" \
  "${ROOT_DIR}/include/api_shuffle.h"

"${HOST_CC}" \
  -I "${ROOT_DIR}/include" \
  "${ROOT_DIR}/loader/exe2h/exe2h.c" \
  -o "${BUILD_DIR}/exe2h"

pushd "${BUILD_DIR}" >/dev/null

LOADER_CFLAGS=(
  -fno-toplevel-reorder
  -fno-builtin
  -fpack-struct=8
  -fPIC
  -O1
  -nostdlib
)
LOADER_SRCS=(
  "${ROOT_DIR}/loader/loader.c"
  "${ROOT_DIR}/loader/depack.c"
  "${ROOT_DIR}/loader/clib.c"
  "${ROOT_DIR}/hash.c"
  "${ROOT_DIR}/encrypt.c"
)

"${MINGW_CC}" \
  -DPEB_WALK_ORDER=1 \
  "${LOADER_CFLAGS[@]}" \
  "${LOADER_SRCS[@]}" \
  -I "${ROOT_DIR}/include" \
  -o loader_peb1.exe
"${BUILD_DIR}/exe2h" loader_peb1.exe

"${MINGW_CC}" \
  -DPEB_WALK_ORDER=2 \
  "${LOADER_CFLAGS[@]}" \
  "${LOADER_SRCS[@]}" \
  -I "${ROOT_DIR}/include" \
  -o loader_peb2.exe
"${BUILD_DIR}/exe2h" loader_peb2.exe

"${MINGW_CC}" \
  "${LOADER_CFLAGS[@]}" \
  "${ROOT_DIR}/loader/dispatch_shim.c" \
  -I "${ROOT_DIR}/include" \
  -o dispatch_shim.exe
"${BUILD_DIR}/exe2h" dispatch_shim.exe

GENERATED_HEADERS=(
  loader_peb1_exe_x64.h
  loader_peb1_fn_table_x64.h
  loader_peb1_ref_table_x64.h
  loader_peb2_exe_x64.h
  loader_peb2_fn_table_x64.h
  loader_peb2_ref_table_x64.h
  dispatch_shim_exe_x64.h
)

for header in "${GENERATED_HEADERS[@]}"; do
  if [[ ! -f "${header}" ]]; then
    echo "missing generated header: ${header}" >&2
    exit 1
  fi
  mv "${header}" "${GENERATED_DIR}/"
done

popd >/dev/null

echo "generated loader headers in ${GENERATED_DIR}"
