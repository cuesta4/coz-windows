/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include "win_hooks.h"

#include "perf.h"
#include "thread_state.h"

namespace real {
  NTSTATUS (NTAPI* NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER) =
    reinterpret_cast<decltype(NtWaitForSingleObject)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWaitForSingleObject"));
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
