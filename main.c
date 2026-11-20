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

static int RunInjection(void)
{
	printf("UserModeInjector - research DLL injection against a SELF-SPAWNED consenting child only\n\n");

	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	FARPROC loadLibraryW = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : NULL;
	if (loadLibraryW == NULL)
	{
		PrintLastError("GetProcAddress(LoadLibraryW)");
		return EXIT_FAILURE;
	}

	WCHAR payloadPath[MAX_PATH * 2] = { 0 };
	if (!ResolvePayloadPath(payloadPath, _countof(payloadPath)))
	{
		return EXIT_FAILURE;
	}
	printf("[+] Payload DLL: %ls\n", payloadPath);

	WCHAR exePath[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0)
	{
		PrintLastError("GetModuleFileNameW");
		return EXIT_FAILURE;
	}

	WCHAR markerPath[MAX_PATH * 2] = { 0 };
	DWORD tempLength = GetTempPathW(MAX_PATH, markerPath, _countof(markerPath));
	if (tempLength == 0 || tempLength >= MAX_PATH)
	{
		PrintLastError("GetTempPathW");
		return EXIT_FAILURE;
	}
	_snwprintf_s(markerPath + tempLength, _countof(markerPath) - tempLength, _TRUNCATE,
		L"injector-marker-%lu.txt", GetCurrentProcessId());
	if (!SetEnvironmentVariableW(L"INJECTOR_MARKER", markerPath))
	{
		PrintLastError("SetEnvironmentVariableW(INJECTOR_MARKER)");
		return EXIT_FAILURE;
	}
	printf("[+] Marker path (inherited by the child): %ls\n", markerPath);

	// Step 1: spawn the consenting child suspended.
	WCHAR commandLine[MAX_PATH + 16] = { 0 };
	_snwprintf_s(commandLine, _countof(commandLine), _TRUNCATE, L"\"%ls\" --child", exePath);
	STARTUPINFOW startup = { sizeof(startup) };
	PROCESS_INFORMATION child = { 0 };
	if (!CreateProcessW(exePath, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child))
	{
		PrintLastError("CreateProcessW(child, SUSPENDED)");
		return EXIT_FAILURE;
	}
	printf("[+] Step 1 SPAWN: consenting child started suspended, PID %lu, main thread %lu\n",
		child.dwProcessId, child.dwThreadId);

	int result = EXIT_FAILURE;
	HANDLE remoteThread = NULL;
	LPVOID remoteBuffer = NULL;
	BOOL injected = FALSE;

	// A suspended child has not run its loader yet: kernel32 is not mapped and
	// module enumeration fails with E299 (partial copy). Resume first, then
	// wait for kernel32 to appear so the base check happens BEFORE any write.
	DWORD previousCount = ResumeThread(child.hThread);
	if (previousCount == (DWORD)-1)
	{
		PrintLastError("ResumeThread(child)");
		goto cleanup;
	}
	printf("[+] Step 1 SPAWN: child resumed (previous suspend count %lu); waiting for its loader\n",
		(unsigned long)previousCount);

	HANDLE inspectable = NULL;
	BOOL baseVerified = FALSE;
	for (DWORD attempt = 0; attempt < 50 && !baseVerified; attempt++)
	{
		if (inspectable != NULL)
		{
			CloseHandle(inspectable);
			inspectable = NULL;
		}
		inspectable = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, child.dwProcessId);
		if (inspectable == NULL)
		{
			Sleep(100);
			continue;
		}
		baseVerified = VerifyRemoteKernel32Base(inspectable, kernel32, attempt == 49);
		if (!baseVerified)
		{
			Sleep(100);
		}
	}
	if (inspectable != NULL)
	{
		CloseHandle(inspectable);
	}
	if (!baseVerified)
	{
		fprintf(stderr, "[-] kernel32 base not verified in the child; refusing to inject\n");
		goto cleanup;
	}

	// Step 2: allocate the path buffer in the child.
	SIZE_T pathBytes = (wcslen(payloadPath) + 1) * sizeof(WCHAR);
	remoteBuffer = VirtualAllocEx(child.hProcess, NULL, pathBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteBuffer == NULL)
	{
		PrintLastError("VirtualAllocEx(child)");
		goto cleanup;
	}
	printf("[+] Step 2 ALLOCATE: %llu bytes PAGE_READWRITE in the child at %p\n",
		(unsigned long long)pathBytes, remoteBuffer);

	// Step 3: write the payload path and verify by read-back.
	SIZE_T written = 0;
	if (!WriteProcessMemory(child.hProcess, remoteBuffer, payloadPath, pathBytes, &written) || written != pathBytes)
	{
		PrintLastError("WriteProcessMemory(child)");
		goto cleanup;
	}
	WCHAR readBack[MAX_PATH * 2] = { 0 };
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(child.hProcess, remoteBuffer, readBack, pathBytes, &bytesRead) ||
		bytesRead != pathBytes || memcmp(readBack, payloadPath, pathBytes) != 0)
	{
		fprintf(stderr, "[-] Read-back verification of the written path failed\n");
		goto cleanup;
	}
	printf("[+] Step 3 WRITE: %llu bytes written and read-back verified\n", (unsigned long long)written);

	// Step 4: execute through a remote thread running LoadLibraryW.
	DWORD remoteThreadId = 0;
	remoteThread = CreateRemoteThread(
		child.hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)loadLibraryW, remoteBuffer, 0, &remoteThreadId);
	if (remoteThread == NULL)
	{
		PrintLastError("CreateRemoteThread(LoadLibraryW)");
		goto cleanup;
	}
	printf("[+] Step 4 EXECUTE: remote thread %lu started at kernel32!LoadLibraryW(%p)\n",
		remoteThreadId, remoteBuffer);

	DWORD wait = WaitForSingleObject(remoteThread, THREAD_WAIT_MS);
	if (wait != WAIT_OBJECT_0)
	{
		fprintf(stderr, "[-] Remote thread wait %s after %lu ms\n",
			wait == WAIT_TIMEOUT ? "timed out" : "failed", THREAD_WAIT_MS);
		goto cleanup;
	}
	DWORD threadExit = 0;
	if (!GetExitCodeThread(remoteThread, &threadExit))
	{
		PrintLastError("GetExitCodeThread");
		goto cleanup;
	}
	printf("[+] Remote thread exited; LoadLibraryW returned 0x%08lX (nonzero = module handle low bits)\n",
		(unsigned long)threadExit);
	if (threadExit == 0)
	{
		fprintf(stderr, "[-] LoadLibraryW returned NULL inside the child; the payload did not load\n");
		goto cleanup;
	}
	injected = TRUE;

	// Step 5: collect both execution proofs (the child is already running).
	printf("[+] Step 5 PROOF: waiting for the payload's marker file\n");

	BOOL markerSeen = WaitForMarkerFile(markerPath, MARKER_WAIT_MS);
	if (markerSeen)
	{
		FILE* marker = _wfopen(markerPath, L"r");
		if (marker != NULL)
		{
			char line[256] = { 0 };
			if (fgets(line, sizeof(line), marker) != NULL)
			{
				printf("[+] Marker proof: %s", line);
			}
			fclose(marker);
		}
	}
	else
	{
		fprintf(stderr, "[-] Marker file did not appear within %lu ms\n", MARKER_WAIT_MS);
	}

	HMODULE payloadModule = NULL;
	HANDLE listable = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, child.dwProcessId);
	BOOL moduleSeen = FALSE;
	if (listable != NULL)
	{
		moduleSeen = FindChildModule(listable, L"InjectorPayload.dll", &payloadModule);
		CloseHandle(listable);
	}
	if (moduleSeen)
	{
		printf("[+] Module proof: InjectorPayload.dll present in the child at %p\n", (LPCVOID)payloadModule);
	}
	else
	{
		fprintf(stderr, "[-] InjectorPayload.dll not found in the child's module list\n");
	}

	result = (markerSeen && moduleSeen) ? EXIT_SUCCESS : EXIT_FAILURE;
	printf("[+] Injection %s\n", result == EXIT_SUCCESS ? "demonstrated: both proofs collected" : "NOT proven: missing proof(s)");

cleanup:
	// Step 6: account for every child-side change and every handle.
	if (remoteBuffer != NULL && child.hProcess != NULL)
	{
		if (VirtualFreeEx(child.hProcess, remoteBuffer, 0, MEM_RELEASE))
		{
			printf("[+] Step 6 CLEANUP: remote buffer freed\n");
		}
		else
		{
			PrintLastError("VirtualFreeEx(remote buffer)");
		}
	}
	if (remoteThread != NULL)
	{
		CloseHandle(remoteThread);
		printf("[+] Step 6 CLEANUP: remote thread handle closed\n");
	}
	if (child.hProcess != NULL)
	{
		if (injected || result == EXIT_FAILURE)
		{
			if (TerminateProcess(child.hProcess, 0))
			{
				WaitForSingleObject(child.hProcess, CHILD_EXIT_WAIT_MS);
				printf("[+] Step 6 CLEANUP: child terminated by the injector\n");
			}
			else
			{
				PrintLastError("TerminateProcess(child)");
			}
		}
		CloseHandle(child.hProcess);
	}
	if (child.hThread != NULL)
	{
		CloseHandle(child.hThread);
	}
	DeleteFileW(markerPath);
	SetEnvironmentVariableW(L"INJECTOR_MARKER", NULL);
	printf("[+] Step 6 CLEANUP: marker deleted, environment restored, handles closed\n");
	return result;
}

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		return RunInjection();
	}
	if (argc == 2 && strcmp(argv[1], "--plan") == 0)
	{
		return RunPlan();
	}
	if (argc == 2 && strcmp(argv[1], "--child") == 0)
	{
		return RunChild();
	}
	fprintf(stderr, "Usage: %s              full injection run (self-spawned consenting child only)\n", argv[0]);
	fprintf(stderr, "       %s --plan       read-only resolution; opens no process\n", argv[0]);
	fprintf(stderr, "       %s --child      consenting child role (used internally)\n", argv[0]);
	fprintf(stderr, "This tool refuses arbitrary PID targets by design; it only injects into its own child.\n");
	return 2;
}
