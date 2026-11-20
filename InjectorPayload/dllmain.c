// InjectorPayload - proof-of-execution payload for the UserModeInjector
// research exercise. When this DLL is loaded inside the target child (through
// the injector's CreateRemoteThread + LoadLibraryW flow), DllMain writes a
// marker file to the path given by the INJECTOR_MARKER environment variable
// (inherited from the injector). The marker is the child-side proof that the
// injected code actually executed.
//
// Loader-lock caveat: file I/O from DllMain is not best practice (the loader
// lock is held). It is acceptable here because kernel32 is already initialized
// and the payload is a self-contained research proof, not production code.

#include <Windows.h>
#include <stdio.h>

static void WriteMarker(void)
{
	WCHAR markerPath[MAX_PATH * 2] = { 0 };
	DWORD length = GetEnvironmentVariableW(L"INJECTOR_MARKER", markerPath, _countof(markerPath));
	if (length == 0 || length >= _countof(markerPath))
	{
		return;
	}

	HANDLE file = CreateFileW(
		markerPath,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		return;
	}

	char content[256] = { 0 };
	int written = _snprintf_s(
		content,
		sizeof(content),
		_TRUNCATE,
		"InjectorPayload DllMain executed in PID %lu\n",
		GetCurrentProcessId());
	DWORD bytesWritten = 0;
	WriteFile(file, content, (DWORD)written, &bytesWritten, NULL);
	CloseHandle(file);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	UNREFERENCED_PARAMETER(module);
	UNREFERENCED_PARAMETER(reserved);
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
			WriteMarker();
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
