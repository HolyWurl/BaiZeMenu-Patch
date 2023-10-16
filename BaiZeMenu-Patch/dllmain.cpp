#include "pch.h"
#pragma execution_character_set("utf-8")
DWORD WINAPI go(LPVOID lp)
{
    if (AllocConsole()) {
        freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    }

    uint64_t base_addr = NULL;
    do
    {
        base_addr = (uint64_t)GetModuleHandleA("BaiZe.dll");
        std::this_thread::yield();
        std::cout << "Waiting BaiZe.dll to patch" << std::endl;
    } while (!base_addr);

    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll != NULL)
    {
        auto addr = GetProcAddress(ntdll, "NtProtectVirtualMemory");
        byte vmpbyte[] = { 0x4C,0x8B,0xD1,0xB8,0x50 };  //修补VMP内存保护
        PDWORD O1;
        if (VirtualProtect(addr, sizeof(vmpbyte) + 1, PAGE_EXECUTE_READWRITE, (PDWORD)&O1) != 0)
        {
            if (memcmp(addr, vmpbyte, sizeof(vmpbyte)) != 0)
            {
                memcpy(addr, vmpbyte, sizeof(vmpbyte));
            }
        }
    }
    byte pbyte[] = { 0x0F, 0x85 };  //验证错误跳转
    PDWORD O;
    auto off = base_addr + 0x26DCA6;
    if (VirtualProtect((void*)off, sizeof(pbyte) + 1, PAGE_EXECUTE_READWRITE, (PDWORD)&O) != 0)
    {
        if (memcmp((void*)off, pbyte, sizeof(pbyte)) != 0)
        {
            memcpy((void*)off, pbyte, sizeof(pbyte));
        }
    }
    byte pbyte1[] = { 0x75 };   //防篡改g_running为false
    off = base_addr + 0x26E535;
    if (VirtualProtect((void*)off, sizeof(pbyte1) + 1, PAGE_EXECUTE_READWRITE, (PDWORD)&O) != 0)
    {
        if (memcmp((void*)off, pbyte1, sizeof(pbyte1)) != 0)
        {
            memcpy((void*)off, pbyte1, sizeof(pbyte1));
        }
    }
    byte pbyte3[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };   //此函数会导致崩溃所以nop
    off = base_addr + 0x26E3C7;
    if (VirtualProtect((void*)off, sizeof(pbyte3) + 1, PAGE_EXECUTE_READWRITE, (PDWORD)&O) != 0)
    {
        if (memcmp((void*)off, pbyte3, sizeof(pbyte3)) != 0)
        {
            memcpy((void*)off, pbyte3, sizeof(pbyte3));
        }
    }
    while (true)
    {
        *(bool*)(base_addr + 0x566694) = true;  //确保g_runnning永远为true不会卸载
        SetConsoleTitleW(L"Cracked by HolyWu | 白泽破解交流群939816109");
    }
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, go, nullptr, 0, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

