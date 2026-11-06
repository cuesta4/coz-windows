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

/// What a synchronization hook does around the original call, and when the wake-up skips delays
enum { Catch = 1, Block = 2, Loader = 4 };
enum { SkipAlways, SkipWait, SkipZero };

/// Hooks with the common skeleton: module, function, return type, parameters, arguments,
/// Catch (pay the delays before the call can wake a thread), Block (the call can block), Loader
/// (not for the loader lock), and which results skip delays. Wait statuses skip for WAIT_n and ABANDONED_n
#define SYNC(X) \
  X(L"ntdll.dll", RtlAcquireSRWLockExclusive, VOID, (PVOID a), (a), Block, SkipAlways) \
  X(L"ntdll.dll", RtlAcquireSRWLockShared, VOID, (PVOID a), (a), Block, SkipAlways) \
  X(L"ntdll.dll", RtlReleaseSRWLockExclusive, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", RtlReleaseSRWLockShared, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", RtlEnterCriticalSection, NTSTATUS, (PVOID a), (a), Block | Loader, SkipAlways) \
  X(L"ntdll.dll", RtlLeaveCriticalSection, NTSTATUS, (PVOID a), (a), Catch | Loader, SkipAlways) \
  X(L"ntdll.dll", RtlSleepConditionVariableSRW, NTSTATUS, (PVOID a, PVOID b, PLARGE_INTEGER c, ULONG d), (a, b, c, d), Block, SkipZero) \
  X(L"ntdll.dll", RtlSleepConditionVariableCS, NTSTATUS, (PVOID a, PVOID b, PLARGE_INTEGER c), (a, b, c), Block, SkipZero) \
  X(L"ntdll.dll", RtlWakeConditionVariable, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", RtlWakeAllConditionVariable, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", RtlWaitOnAddress, NTSTATUS, (volatile VOID* a, PVOID b, SIZE_T c, PLARGE_INTEGER d), (a, b, c, d), Block, SkipZero) \
  X(L"ntdll.dll", RtlWakeAddressSingle, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", RtlWakeAddressAll, VOID, (PVOID a), (a), Catch, SkipAlways) \
  X(L"ntdll.dll", NtWaitForSingleObject, NTSTATUS, (HANDLE a, BOOLEAN b, PLARGE_INTEGER c), (a, b, c), Block, SkipWait) \
  X(L"ntdll.dll", NtWaitForMultipleObjects, NTSTATUS, (ULONG a, HANDLE* b, int c, BOOLEAN d, PLARGE_INTEGER e), (a, b, c, d, e), Block, SkipWait) \
  X(L"ntdll.dll", NtSignalAndWaitForSingleObject, NTSTATUS, (HANDLE a, HANDLE b, BOOLEAN c, PLARGE_INTEGER d), (a, b, c, d), Catch | Block, SkipWait) \
  X(L"ntdll.dll", NtSetEvent, NTSTATUS, (HANDLE a, PLONG b), (a, b), Catch, SkipAlways) \
  X(L"ntdll.dll", NtPulseEvent, NTSTATUS, (HANDLE a, PLONG b), (a, b), Catch, SkipAlways) \
  X(L"ntdll.dll", NtReleaseSemaphore, NTSTATUS, (HANDLE a, LONG b, PLONG c), (a, b, c), Catch, SkipAlways) \
  X(L"ntdll.dll", NtReleaseMutant, NTSTATUS, (HANDLE a, PLONG b), (a, b), Catch, SkipAlways) \
  X(L"ntdll.dll", NtRemoveIoCompletion, NTSTATUS, (HANDLE a, PVOID* b, PVOID* c, PVOID d, PLARGE_INTEGER e), (a, b, c, d, e), Block, SkipZero) \
  X(L"ntdll.dll", NtRemoveIoCompletionEx, NTSTATUS, (HANDLE a, PVOID b, ULONG c, PULONG d, PLARGE_INTEGER e, BOOLEAN f), (a, b, c, d, e, f), Block, SkipZero) \
  X(L"ntdll.dll", NtSetIoCompletion, NTSTATUS, (HANDLE a, PVOID b, PVOID c, NTSTATUS d, ULONG_PTR e), (a, b, c, d, e), Catch, SkipAlways)

/// Every hook is a row: module, function. The custom ones need a real:: pointer below and a
/// hook_<function>; the SYNC ones get both from their row
#define HOOKS(X) \
  X(L"ntdll.dll", RtlExitUserProcess) \
  X(L"ntdll.dll", RtlExitUserThread) \
  X(L"ntdll.dll", NtDelayExecution) \
  X(L"kernelbase.dll", CreateRemoteThreadEx) \
  SYNC(X)

#define REAL(module, name, ret, params, ...) \
  ret (NTAPI* name) params = reinterpret_cast<decltype(name)>(GetProcAddress(GetModuleHandleW(module), #name));

namespace real {
  SYNC(REAL)
  VOID (NTAPI* RtlExitUserProcess)(NTSTATUS) =
    reinterpret_cast<decltype(RtlExitUserProcess)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlExitUserProcess"));
  VOID (NTAPI* RtlExitUserThread)(NTSTATUS) =
    reinterpret_cast<decltype(RtlExitUserThread)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlExitUserThread"));
  NTSTATUS (NTAPI* NtDelayExecution)(BOOLEAN, PLARGE_INTEGER) =
    reinterpret_cast<decltype(NtDelayExecution)>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution"));
  HANDLE (WINAPI* CreateRemoteThreadEx)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                        LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD) =
    reinterpret_cast<decltype(CreateRemoteThreadEx)>(
      GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CreateRemoteThreadEx"));
}

/// The state of the calling thread if it is registered and coz is running. Unlike a bare
/// TlsGetValue it keeps the last error
static thread_state* tls_state() {
  DWORD error = GetLastError();
  thread_state* state = initialized ? static_cast<thread_state*>(TlsGetValue(g_tls)) : nullptr;
  SetLastError(error);
  return state;
}

/// Result of the original call. The void one skips delays, like a lock acquire
template<class R> struct result {
  R value;
  template<class F> explicit result(F f) : value(f()) {}
  bool skip(int mode) const {
    if(mode == SkipWait) return (value >= 0 && value <= 0x3F) || (value >= 0x80 && value <= 0xBF);
    return mode == SkipAlways || value == 0;
  }
  R get() const { return value; }
};
template<> struct result<void> {
  template<class F> explicit result(F f) { f(); }
  bool skip(int) const { return true; }
  void get() const {}
};

/// The PEB LoaderLock, read when the hooks are installed. Delaying a thread that holds it would stall the process
static void* g_loader_lock = nullptr;

bool win_holds_loader_lock() {
  // DllMain and TLS callbacks of every DLL run with it held, including thread attach and detach
  const RTL_CRITICAL_SECTION* cs = static_cast<const RTL_CRITICAL_SECTION*>(g_loader_lock);
  return cs != nullptr && cs->OwningThread == (HANDLE)(ULONG_PTR)GetCurrentThreadId();
}

template<class T, class... R> static void* first(T t, R...) { return (void*)(ULONG_PTR)t; }

/// Common skeleton of the synchronization hooks. in_hook covers the original call too, so the
/// nested ntdll calls pass through. The error is read before coz calls anything that changes it
template<int F, int M, class Fn, class... A>
static auto hooked(Fn& fn, A... a) -> decltype(fn(a...)) {
  typedef decltype(fn(a...)) R;
  thread_state* state = tls_state();
  if(state == nullptr || state->in_hook || ((F & Loader) && first(a...) == g_loader_lock) ||
     win_holds_loader_lock())
    return fn(a...);

  profiler& p = profiler::get_instance();
  state->in_hook = true;
  if(F & Catch) p.catch_up();
  if(F & Block) p.pre_block();
  result<R> r([&] { return fn(a...); });
  DWORD error = GetLastError();
  if(F & Block) p.post_block(r.skip(M));
  state->in_hook = false;
  SetLastError(error);
  return r.get();
}

#define ARGS(...) __VA_ARGS__
#define SYNC_HOOK(module, name, ret, params, args, flags, skip) \
  static ret NTAPI hook_##name params { return hooked<flags, skip>(real::name, ARGS args); }
SYNC(SYNC_HOOK)

/// The CRT of a /MT target is already torn down when this runs, so only coz's own CRT is used
static VOID NTAPI hook_RtlExitUserProcess(NTSTATUS status) {
  if(initialized) coz_shutdown_process();
  real::RtlExitUserProcess(status);
}

/// Pay the pending delays before the thread exits, as it may be what a join is waiting for
static VOID NTAPI hook_RtlExitUserThread(NTSTATUS status) {
  thread_state* state = tls_state();
  if(state != nullptr && !state->in_hook) {
    profiler::get_instance().exit_thread();
  }
  real::RtlExitUserThread(status);
}

/// Only protects the processing APC, which would cut an alertable sleep short.
/// It has no blocking semantics, like nanosleep on Linux
static NTSTATUS NTAPI hook_NtDelayExecution(BOOLEAN alertable, PLARGE_INTEGER interval) {
  thread_state* state = tls_state();
  if(state == nullptr || state->in_hook || !alertable)
    return real::NtDelayExecution(alertable, interval);

  state->sampler.no_apc.store(true);
  NTSTATUS result = real::NtDelayExecution(alertable, interval);
  state->sampler.no_apc.store(false);
  return result;
}

/// Entry point of the threads created in this process: starts them with their parent delay count
static DWORD WINAPI coz_thread_trampoline(LPVOID p) {
  thread_start_arg* arg = static_cast<thread_start_arg*>(p);
  thread_fn_t fn = arg->_fn;
  void* fn_arg = arg->_arg;

  // The thread registered itself in DLL_THREAD_ATTACH, before getting here
  thread_state* state = tls_state();
  if(state != nullptr) state->local_delay.store(arg->_parent_delay_time);
  delete arg;

  return fn(fn_arg);
}

static HANDLE WINAPI hook_CreateRemoteThreadEx(HANDLE process, LPSECURITY_ATTRIBUTES attributes,
                                               SIZE_T stack_size, LPTHREAD_START_ROUTINE fn, LPVOID arg,
                                               DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST list, LPDWORD id) {
  thread_state* state = tls_state();
  if(state == nullptr || state->in_hook ||
     (process != GetCurrentProcess() && GetProcessId(process) != GetCurrentProcessId()))
    return real::CreateRemoteThreadEx(process, attributes, stack_size, fn, arg, flags, list, id);

  state->in_hook = true;
  thread_start_arg* wrapped = new thread_start_arg(fn, arg, state->local_delay.load());
  HANDLE thread = real::CreateRemoteThreadEx(process, attributes, stack_size, coz_thread_trampoline,
                                             wrapped, flags, list, id);
  DWORD error = GetLastError();
  if(thread == nullptr) delete wrapped;
  state->in_hook = false;
  SetLastError(error);
  return thread;
}

static DWORD (WINAPI* real_entry)(LPVOID) = nullptr;

/// Runs in place of the program's entry point: on the main thread, outside the loader lock
static DWORD WINAPI coz_entry(LPVOID peb) {
  // x64: TEB+0x60 is the PEB, PEB+0x110 is LoaderLock
  g_loader_lock = *reinterpret_cast<void**>(__readgsqword(0x60) + 0x110);

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

#define ATTACH(module, name, ...)   REQUIRE(DetourAttach(&(PVOID&)real::name, (PVOID)hook_##name) == NO_ERROR) << "Failed to hook " #name;
  HOOKS(ATTACH)
#undef ATTACH
  REQUIRE(DetourTransactionCommit() == NO_ERROR) << "Failed to install the hooks";
  for(HANDLE t : threads) CloseHandle(t);

  init_coz();
  return real_entry(peb);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
  if(reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH) {
    // Threads created before this DLL attached never get here: the main thread is registered by
    // startup(), and the loader workers never run user code
    if(g_tls == TLS_OUT_OF_INDEXES) return TRUE;
    DWORD tid = GetCurrentThreadId();
    for(auto& t : g_internal_tids) {
      if(t.load() == tid) return TRUE;
    }

    // Both run under the loader lock: no waiting, and never a delay
    if(reason == DLL_THREAD_ATTACH) profiler::get_instance().attach_thread();
    else profiler::get_instance().detach_thread();
  }
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
HANDLE g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
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
  return state != nullptr ? state->wait_timer : nullptr;
}
