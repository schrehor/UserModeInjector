// UserModeInjector - research-purpose user-mode process injector.
//
// The classic allocate -> write -> execute flow (MITRE ATT&CK T1055.001, DLL
// injection via CreateRemoteThread + LoadLibraryW), demonstrated ONLY against
// a self-spawned consenting child process that this program creates suspended
// and terminates itself. No other target is accepted.
//
// Modes:
//   (no args)   full injection run against a self-spawned child
//   --plan      read-only: resolve and print LoadLibraryW and sizes; opens no
//               process
//   --child     consenting child role: waits until terminated by the injector
//
// Every step prints explicit diagnostics with GetLastError on failure and all
// child-side resources are freed and all handles closed on every path.

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

#define CHILD_WAIT_SECONDS   120u
#define THREAD_WAIT_MS       10000u
#define MARKER_WAIT_MS       5000u
#define CHILD_EXIT_WAIT_MS   10000u

static void PrintLastError(const char* step)
{
	fprintf(stderr, "[-] %s failed: E%lu\n", step, GetLastError());
}

// The consenting child role: stay alive quietly until the injector terminates
// this process after the injection proof completes.
static int RunChild(void)
{
	printf("[+] Child PID %lu waiting (consenting injection target; the injector terminates this process)\n",
		GetCurrentProcessId());
	fflush(NULL);
	for (DWORD i = 0; i < CHILD_WAIT_SECONDS; i++)
	{
		Sleep(1000);
	}
	printf("[+] Child wait window elapsed; exiting normally\n");
	return 0;
}

// Resolve the payload DLL path next to this executable's build tree.
static BOOL ResolvePayloadPath(WCHAR* buffer, DWORD capacity)
{
	WCHAR exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0)
	{
		PrintLastError("GetModuleFileNameW");
		return FALSE;
	}
	WCHAR* lastSlash = wcsrchr(exePath, L'\\');
	if (lastSlash == NULL)
	{
		fprintf(stderr, "[-] Cannot derive the repository root from %ls\n", exePath);
		return FALSE;
	}
	*lastSlash = L'\0'; // exe directory: <root>\x64\<Configuration>
	WCHAR* configSlash = wcsrchr(exePath, L'\\');
	if (configSlash == NULL)
	{
		fprintf(stderr, "[-] Unexpected executable path shape: %ls\n", exePath);
		return FALSE;
	}
	*configSlash = L'\0'; // <root>\x64
	WCHAR* rootSlash = wcsrchr(exePath, L'\\');
	if (rootSlash == NULL)
	{
		fprintf(stderr, "[-] Unexpected executable path shape: %ls\n", exePath);
		return FALSE;
	}
	*rootSlash = L'\0'; // <root>

#ifdef _DEBUG
	const WCHAR* configuration = L"Debug";
#else
	const WCHAR* configuration = L"Release";
#endif
	int written = _snwprintf_s(buffer, capacity, _TRUNCATE,
		L"%ls\\InjectorPayload\\x64\\%ls\\InjectorPayload.dll", exePath, configuration);
	if (written <= 0 || (DWORD)written >= capacity)
	{
		fprintf(stderr, "[-] Payload path does not fit the buffer\n");
		return FALSE;
	}
	if (GetFileAttributesW(buffer) == INVALID_FILE_ATTRIBUTES)
	{
		fprintf(stderr, "[-] Payload DLL not found: %ls (build it first)\n", buffer);
		return FALSE;
	}
	return TRUE;
}

// Compare the child's kernel32.dll base with the local one. System DLL bases
// are identical across processes for one boot (same physical pages), which is
// what makes the local LoadLibraryW address usable remotely; this check makes
// that assumption observable instead of silent.
static BOOL VerifyRemoteKernel32Base(HANDLE child, HMODULE localKernel32, BOOL verbose)
{
	HMODULE modules[512] = { 0 };
	DWORD needed = 0;
	if (!K32EnumProcessModules(child, modules, sizeof(modules), &needed))
	{
		if (verbose)
		{
			PrintLastError("K32EnumProcessModules(child)");
		}
		return FALSE;
	}
	DWORD count = needed / sizeof(HMODULE);
	if (count > 512)
	{
		count = 512;
	}
	for (DWORD i = 0; i < count; i++)
	{
		WCHAR name[MAX_PATH] = { 0 };
		if (GetModuleFileNameExW(child, modules[i], name, MAX_PATH) == 0)
		{
			continue;
		}
		WCHAR* baseName = wcsrchr(name, L'\\');
		baseName = baseName ? baseName + 1 : name;
		if (_wcsicmp(baseName, L"kernel32.dll") == 0)
		{
			printf("[+] Child kernel32.dll base: %p; local base: %p -> %s\n",
				(LPCVOID)modules[i],
				(LPCVOID)localKernel32,
				modules[i] == localKernel32 ? "MATCH (local LoadLibraryW address is usable remotely)"
											: "MISMATCH (refusing to inject)");
			return modules[i] == localKernel32;
		}
	}
	if (verbose)
	{
		fprintf(stderr, "[-] kernel32.dll not found among the child's first %lu modules\n", (unsigned long)count);
	}
	return FALSE;
}

static int RunPlan(void)
{
	printf("UserModeInjector --plan: read-only resolution; no process is opened or modified\n");

	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	if (kernel32 == NULL)
	{
		PrintLastError("GetModuleHandleW(kernel32)");
		return EXIT_FAILURE;
	}
	FARPROC loadLibraryW = GetProcAddress(kernel32, "LoadLibraryW");
	if (loadLibraryW == NULL)
	{
		PrintLastError("GetProcAddress(LoadLibraryW)");
		return EXIT_FAILURE;
	}
	printf("[+] Local kernel32.dll base: %p\n", (LPCVOID)kernel32);
	printf("[+] kernel32!LoadLibraryW: %p (remote thread start routine)\n", (LPCVOID)loadLibraryW);

	WCHAR payloadPath[MAX_PATH * 2] = { 0 };
	if (!ResolvePayloadPath(payloadPath, _countof(payloadPath)))
	{
		return EXIT_FAILURE;
	}
	SIZE_T pathBytes = (wcslen(payloadPath) + 1) * sizeof(WCHAR);
	printf("[+] Payload DLL: %ls\n", payloadPath);
	printf("[+] Remote path buffer: %llu bytes (VirtualAllocEx PAGE_READWRITE)\n",
		(unsigned long long)pathBytes);
	printf("[+] Flow: CreateProcessW(self, --child, SUSPENDED) -> resume -> wait for the child's loader\n");
	printf("    -> verify child kernel32 base == local base -> VirtualAllocEx -> WriteProcessMemory\n");
	printf("    -> CreateRemoteThread(LoadLibraryW, path) -> marker + module-list proof\n");
	printf("    -> VirtualFreeEx -> TerminateProcess -> handle cleanup -> marker deletion\n");
	printf("[+] ASSESSMENT: plan resolved; no process was opened or modified\n");
	return EXIT_SUCCESS;
}

static BOOL WaitForMarkerFile(const WCHAR* markerPath, DWORD timeoutMs)
{
	DWORD waited = 0;
	while (waited < timeoutMs)
	{
		DWORD attributes = GetFileAttributesW(markerPath);
		if (attributes != INVALID_FILE_ATTRIBUTES)
		{
			return TRUE;
		}
		Sleep(100);
		waited += 100;
	}
	return FALSE;
}

static BOOL FindChildModule(HANDLE child, const WCHAR* wantedBaseName, HMODULE* found)
{
	HMODULE modules[512] = { 0 };
	DWORD needed = 0;
	if (!K32EnumProcessModules(child, modules, sizeof(modules), &needed))
	{
		PrintLastError("K32EnumProcessModules(child)");
		return FALSE;
	}
	DWORD count = needed / sizeof(HMODULE);
	if (count > 512)
	{
		count = 512;
	}
	for (DWORD i = 0; i < count; i++)
	{
		WCHAR name[MAX_PATH] = { 0 };
		if (GetModuleFileNameExW(child, modules[i], name, MAX_PATH) == 0)
		{
			continue;
		}
		WCHAR* baseName = wcsrchr(name, L'\\');
		baseName = baseName ? baseName + 1 : name;
		if (_wcsicmp(baseName, wantedBaseName) == 0)
		{
			*found = modules[i];
			return TRUE;
		}
	}
	return FALSE;
}

int main(void)
{
	printf("UserModeInjector skeleton\n");
	return 0;
}
