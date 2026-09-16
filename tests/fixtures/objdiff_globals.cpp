volatile int initialized = 0x12345678;
volatile int uninitialized;
extern "C" volatile int values[4] = { 11, 22, 33, 44 };
extern "C" int entry()
{
    uninitialized = initialized + values[2];
    return uninitialized;
}
int main() { return entry(); }
