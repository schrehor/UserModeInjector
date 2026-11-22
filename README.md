# UserModeInjector

A simple x64 user-mode DLL injection PoC for Windows written in C.

Uses `LoadLibraryW` to load a DLL into a newly spawned child process. The injector writes the DLL path into the child and starts a remote thread to load it.

## Build target

Windows x64. Visual Studio with the v145 C/C++ toolset and Windows SDK.

Open `UserModeInjector.slnx` and build both projects in Debug or Release x64.

## Usage

Run `Injector.exe` with `InjectorPayload.dll` built alongside it. A solution build places both in `x64/<Configuration>`.

```powershell
.\x64\Release\Injector.exe
```

The payload serves as a simple demonstration of successful DLL injection. It writes a marker containing the child's PID, and the injector also checks that the DLL appears in the child's module list.

Use `--plan` to print the resolved payload path and planned operations. The injector creates its own target child process.
