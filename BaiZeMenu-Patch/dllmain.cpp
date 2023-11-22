#include "pch.h"
#pragma execution_character_set("utf-8")

void patcher(uint64_t addr, unsigned char* bytes, int numBytes)
{
    DWORD oldProtect;
    VirtualProtect((PVOID)addr, numBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((PVOID)addr, bytes, numBytes);
    VirtualProtect((PVOID)addr, numBytes, oldProtect, &oldProtect);
}

DWORD WINAPI go(LPVOID lp)
{
    //if (AllocConsole()) {
    //    freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
    //    SetConsoleCP(CP_UTF8);
    //    SetConsoleOutputCP(CP_UTF8);
    //}
    //非调试请不要创建控制台
    uint64_t base_addr = NULL;
    do
    {
        base_addr = (uint64_t)GetModuleHandleA("BaiZe.dll");
        std::this_thread::yield();
        //std::cout << "Waiting BaiZe.dll to patch" << std::endl;
    } while (!base_addr);

    auto ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
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
    byte pbyte[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    PDWORD O;
    auto off = base_addr + 0x27C2AB;    //验证函数
    patcher(off, pbyte, 5);
    off = base_addr + 0x27C289; //验证函数
    patcher(off, pbyte, 5);
    off = base_addr + 0x27C29F; //验证函数
    patcher(off, pbyte, 5);
    off = base_addr + 0x27C38A; //检测闪退
    patcher(off, pbyte, 5);
    off = base_addr + 0x27C373; //检测闪退
    patcher(off, pbyte, 5);
    off = base_addr + 0x27CB36; //可能的干扰
    patcher(off, pbyte, 5);
    off = base_addr + 0x27CB3B; //可能的干扰
    patcher(off, pbyte, 5);
    off = base_addr + 0x28B38A; //检测卡死
    patcher(off, pbyte, 5);
    while (true)
    {
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

