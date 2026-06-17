# unlink

This tool takes a win32 .exe as input. Optionally, via a command-line argument one can specify a specific function address, or it will go through all the functions it can find in the .exe. It will then, for each function, extract it into an isolated COFF object file, creating relocations etc. where necessary.
