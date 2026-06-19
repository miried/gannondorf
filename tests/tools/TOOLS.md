## MS Visual C++ 4.2 compiler (invoke with wine)

Compile and link .exe
"""
include=MSDEV/INCLUDE lib=MSDEV/LIB wine MSDEV/BIN/CL.EXE MAIN.CPP
“””

COMPILE to .obj
“””
include=MSDEV/INCLUDE wine MSDEV/BIN/CL.EXE /c MAIN.CPP
“””

## objdiff

A local diffing tool for decompilation projects (https://github.com/encounter/objdiff)

Usage:
"""
./objdiff-cli-macos-arm64
"""

Example `objdiff.json` config file:
{
  "units": [
    {
      "name": "main",
      "target_path": "target/TEST00.obj",
      "base_path": "build/TEST00.obj"
    }
  ]
}

Check online documentation for more information.
