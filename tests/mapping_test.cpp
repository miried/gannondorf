//! FILE TI.EXE
//

#include <windows.h>

struct WinMainStartupArgs
{
    HINSTANCE hInstance;
    LPSTR lpCmdLine;
};

//! FUNC 0x0041bb40
void fn_0041bb40(WinMainStartupArgs& args)
{
}

//! FUNC 0x004321D0
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    WinMainStartupArgs args;

    args.hInstance = hInstance;
    args.lpCmdLine = lpCmdLine;
    fn_0041bb40(args);

    return 0;
}
