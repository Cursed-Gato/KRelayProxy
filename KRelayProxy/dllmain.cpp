#pragma warning( disable : 6031 )
#include "dllmain.h"
#include "BinaryResolver.h"
#include <cstdint>
#include <intsafe.h>

#pragma comment(lib, "ws2_32.lib")

typedef HANDLE(WINAPI* createFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplatefile);
createFileW pCreateFileW = nullptr; //original function pointer after hook
createFileW pCreateFileWTarget;

HANDLE WINAPI detour_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplatefile) {

	if (lpFileName && wcscmp(lpFileName, L"version.dll") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	if (lpFileName && wcscmp(lpFileName, L"dobby.dll") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	if (lpFileName && wcscmp(lpFileName, L"winhttp.dll") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	if (lpFileName && wcscmp(lpFileName, L"winmm.dll") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	if (lpFileName && wcscmp(lpFileName, L"MelonLoader") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	if (lpFileName && wcscmp(lpFileName, L"wininet.dll") == 0) {
		return INVALID_HANDLE_VALUE;
	}

	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplatefile);
}

typedef int (WINAPI* connectFunc)(SOCKET, const sockaddr*, int);
connectFunc pConnectFunc = nullptr;
connectFunc pConnectFuncTarget;

int WINAPI detour_Connect(SOCKET s, const sockaddr* name, int namelen) {
	if (name->sa_family == AF_INET && ntohs(((sockaddr_in*)name)->sin_port) == 2050) {
		((sockaddr_in*)name)->sin_addr.s_addr = inet_addr("127.0.0.1");
	}

	return pConnectFunc(s, name, namelen);
}

void RedirectIOToConsole() {
	AllocConsole();

	FILE* pFile;
	freopen_s(&pFile, "CONOUT$", "w", stdout);
	freopen_s(&pFile, "CONOUT$", "w", stderr);
	freopen_s(&pFile, "CONIN$", "r", stdin);
}

static bool stop = false;

int main() {

	while (!stop) {
		static bool hookEnabled = false;
		if (GetAsyncKeyState(VK_SHIFT) & 0x8000 && GetAsyncKeyState(VK_F9) & 0x8000) {
			if (hookEnabled) {
				MH_DisableHook(reinterpret_cast<void**>(pConnectFuncTarget));
				hookEnabled = false;
				MessageBox(NULL, "Proxy Disabled", "Proxy Status", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
			}
			else {
				MH_EnableHook(reinterpret_cast<void**>(pConnectFuncTarget));
				hookEnabled = true;
				MessageBox(NULL, "Proxy Enabled", "Proxy Status", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL);
			}
			Sleep(100);
		}
		Sleep(10);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		if (MH_Initialize() != MH_OK) {
			return 0;
		}

		if (MH_CreateHookApiEx(L"kernel32", "CreateFileW", detour_CreateFileW, reinterpret_cast<void**>(&pCreateFileW), reinterpret_cast<void**>(&pCreateFileWTarget))) {
			return 1;
		}

		if (MH_CreateHookApiEx(L"Ws2_32.dll", "connect", detour_Connect, reinterpret_cast<void**>(&pConnectFunc), reinterpret_cast<void**>(&pConnectFuncTarget))) {
			return 1;
		}

		if (MH_EnableHook(reinterpret_cast<void**>(pCreateFileWTarget)) != MH_OK) {
			return 1;
		}
		
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, NULL, 0, NULL);

		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		stop = true;
		MH_Uninitialize();
		break;
	}
	return TRUE;
}

