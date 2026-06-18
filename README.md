# unlink

This tool takes a Win32 PE executable as input and extracts discovered functions into isolated COFF object files, creating relocations where necessary.

To extract one known function:

```sh
unlink input.exe --address 0x401000 -o sub_00401000.obj
```

When `--address` is omitted, `unlink` discovers PE32/i386 functions automatically and writes one `sub_XXXXXXXX.obj` file per discovered function. In this mode, `-o/--output` is an output directory:

```sh
unlink input.exe -o extracted-objects
```
