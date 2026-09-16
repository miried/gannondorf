//! FILE globals.exe
extern "C" {
//! DATA 0x00402000 4
volatile int initialized = 0x12345678;
//! DATA 0x00402018 4
volatile int uninitialized;
//! DATA 0x00402008 16
volatile int values[4] = { 11, 22, 33, 44 };
}
//! FUNC 0x00401000
extern "C" int entry()
{
    uninitialized = initialized + values[2];
    return uninitialized;
}
