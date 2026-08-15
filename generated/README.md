This directory holds build-generated loader blob headers used by `fritter.c`.

Generate them with:

```sh
scripts/build-loader-blobs.sh
```

Expected outputs:

- `loader_peb1_exe_x64.h`
- `loader_peb1_fn_table_x64.h`
- `loader_peb1_ref_table_x64.h`
- `loader_peb2_exe_x64.h`
- `loader_peb2_fn_table_x64.h`
- `loader_peb2_ref_table_x64.h`
- `dispatch_shim_exe_x64.h`
