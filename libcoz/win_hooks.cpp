/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include "win_hooks.h"

#include <tlhelp32.h>

#include <detours.h>

#include <vector>

#include "perf.h"
#include "profiler.h"
#include "thread_state.h"

extern bool initialized;

/// Every hook is a row: module, function. Each row needs a real:: pointer in win_hooks.h
/// and a hook_<function> below
#define HOOKS(X)   X(L"ntdll.dll", RtlExitUserProcess)

namespace real {
  NTSTATUS (NTAPI* NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER) =
    reinterpret_cast<decltype(NtWaitForSingleObject)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWaitForSingleObject"));
  VOID (NTAPI* RtlExitUserProcess)(NTSTATUS) =
    reinterpret_cast<decltype(RtlExitUserProcess)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlExitUserProcess"));
}

/// The CRT of a /MT target is already torn down when this runs, so only coz's own CRT is used
static VOID NTAPI hook_RtlExitUserProcess(NTSTATUS status) {
  if(initialized) coz_shutdown_process();
  real::RtlExitUserProcess(status);
}

static DWORD (WINAPI* real_entry)(LPVOID) = nullptr;

/// Runs in place of the program's entry point: on the main thread, outside the loader lock
static DWORD WINAPI coz_entry(LPVOID peb) {
  // The threads that already exist must not be inside a hooked function while it is patched
  std::vector<HANDLE> threads;
  DetourTransactionBegin();
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  THREADENTRY32 te;
  te.dwSize = sizeof(te);
  for(BOOL ok = Thread32First(snapshot, &te); ok; ok = Thread32Next(snapshot, &te)) {
    if(te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
      continue;
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
    if(t != nullptr) {
      DetourUpdateThread(t);
      threads.push_back(t);
    }
  }
  CloseHandle(snapshot);

#define ATTACH(module, name)   REQUIRE(DetourAttach(&(PVOID&)real::name, (PVOID)hook_##name) == NO_ERROR) << "Failed to hook " #name;
  HOOKS(ATTACH)
#undef ATTACH
  REQUIRE(DetourTransactionCommit() == NO_ERROR) << "Failed to install the hooks";
  for(HANDLE t : threads) CloseHandle(t);

  init_coz();
  return real_entry(peb);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
  if(reason == DLL_PROCESS_ATTACH) {
    if(DetourIsHelperProcess()) return TRUE;
    DetourRestoreAfterWith();

    g_tls = TlsAlloc();

    // Never unload: hooks and threads point into this DLL
    HMODULE self;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCWSTR)&DllMain, &self);

    // Under the loader lock only the entry point is patched. Everything else waits for coz_entry
    real_entry = reinterpret_cast<decltype(real_entry)>(DetourGetEntryPoint(NULL));
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)real_entry, (PVOID)coz_entry);
    DetourTransactionCommit();
  }
  return TRUE;
}

DWORD g_tls = TLS_OUT_OF_INDEXES;
size_t g_spin_ns = 1000 * 1000;  // Replaced by the measured value when coz starts
std::atomic<DWORD> g_internal_tids[2];

HANDLE win_create_internal_thread(LPTHREAD_START_ROUTINE fn, LPVOID arg) {
  DWORD tid;
  HANDLE h = CreateThread(nullptr, 0, fn, arg, CREATE_SUSPENDED, &tid);
  if(h != nullptr) {
    // The ID must be known before the thread runs and attaches to the DLL
    for(auto& t : g_internal_tids) {
      DWORD empty = 0;
      if(t.compare_exchange_strong(empty, tid)) break;
    }
    ResumeThread(h);
  }
  return h;
}

HANDLE win_wait_timer() {
  thread_state* state = static_cast<thread_state*>(TlsGetValue(g_tls));
  if(state != nullptr) return state->wait_timer;

  // Internal threads are not registered, so they own their timer
  static thread_local HANDLE timer =
    CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
  return timer;
}
