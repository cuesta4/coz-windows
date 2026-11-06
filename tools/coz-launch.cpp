/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

// Starts a program with coz.dll injected, the Windows counterpart of LD_PRELOAD.
// Usage: coz-launch <path\to\coz.dll> "<quoted command line>"

#include <windows.h>
#include <detours.h>

#include <stdio.h>

#include <string>

// Handling Ctrl+C here keeps the launcher alive while the program, which receives the
// same event, writes its profile and exits
static BOOL WINAPI on_ctrl(DWORD) {
  return TRUE;
}

int wmain(int argc, wchar_t** argv) {
  if(argc != 3) {
    fprintf(stderr, "Usage: coz-launch <path\\to\\coz.dll>\"<command line>\"\n");
    return 2;
  }

  // Detours takes the DLL name as an ANSI string
  char dll[MAX_PATH];
  if(!WideCharToMultiByte(CP_ACP, 0, argv[1], -1, dll, sizeof(dll), NULL, NULL)) {
    fprintf(stderr, "coz-launch: invalid DLL path\n");
    return 2;
  }

  SetConsoleCtrlHandler(on_ctrl, TRUE);

  // The command line is already quoted and is passed to the program verbatim
  std::wstring command_line(argv[2]);
  STARTUPINFOW si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};
  if(!DetourCreateProcessWithDllExW(NULL, &command_line[0], NULL, NULL, TRUE,
                                    CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi, dll, NULL)) {
    fprintf(stderr, "coz-launch: unable to start the program (error %lu)\n", GetLastError());
    return 1;
  }

  CloseHandle(pi.hThread);
  WaitForSingleObject(pi.hProcess, INFINITE);

  DWORD exit_code = 1;
  GetExitCodeProcess(pi.hProcess, &exit_code);
  CloseHandle(pi.hProcess);
  return (int)exit_code;
}
