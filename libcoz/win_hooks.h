/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#if !defined(CAUSAL_RUNTIME_WIN_HOOKS_H)
#define CAUSAL_RUNTIME_WIN_HOOKS_H

#include <windows.h>

#include <atomic>
#include <cstddef>

typedef LONG NTSTATUS;

/// Trampolines to the original ntdll functions. Detours repoints them when it hooks the
/// function, so coz's own code must call these and never the hooked entry points.
namespace real {
  extern NTSTATUS (NTAPI* NtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);
}

namespace real {
  extern VOID (NTAPI* RtlExitUserProcess)(NTSTATUS);
  extern VOID (NTAPI* RtlExitUserThread)(NTSTATUS);
  extern NTSTATUS (NTAPI* NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
  extern HANDLE (WINAPI* CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                               LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
}

/// True while the calling thread owns the loader lock: coz never processes samples or pauses then
bool win_holds_loader_lock();

/// Shuts coz down when the process exits (libcoz.cpp)
void coz_shutdown_process();

extern DWORD g_tls;       //< TLS slot that holds the calling thread's thread_state*
extern size_t g_spin_ns;  //< Time wait() spins at the end of a delay instead of sleeping

/// IDs of coz's own threads. They are never registered, sampled or suspended
extern std::atomic<DWORD> g_internal_tids[2];

/// Create and start a coz internal thread
HANDLE win_create_internal_thread(LPTHREAD_START_ROUTINE fn, LPVOID arg);

/// High-resolution timer of the calling thread, used by wait()
HANDLE win_wait_timer();

#endif
