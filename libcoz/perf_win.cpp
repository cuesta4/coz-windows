/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include "perf.h"

#include <psapi.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "profiler.h"
#include "thread_state.h"
#include "util.h"
#include "win_hooks.h"

#include "ccutil/spinlock.h"

std::atomic<thread_state*> perf_event::slots[perf_event::MaxSlots];
std::atomic<size_t> perf_event::high_water{0};

void perf_event::open(thread_state* owner) {
  state = owner;
  tid = GetCurrentThreadId();
  teb = reinterpret_cast<NT_TIB*>(NtCurrentTeb());

  // The sampler suspends this thread through its own handle
  REQUIRE(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &h,
                          THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                          THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, 0))
    << "Failed to duplicate the thread handle";
  _ring = static_cast<ring*>(VirtualAlloc(nullptr, sizeof(ring), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
  REQUIRE(_ring != nullptr) << "Failed to allocate the sample ring";

  // Thread state slots are reused, so every field is reset here
  QueryThreadCycleTime(h, &last_cycles);
  last_visit = get_time();
  enabled.store(false);
  busy.store(false);
  apc_pending.store(false);
  counting.store(false);
  wake_at.store(0);
  wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  REQUIRE(wake != nullptr) << "Failed to create the delay event";
  no_apc.store(false);
  active.store(true);

  // Publishing the slot makes this thread visible to the sampler
  size_t i = 0;
  for(;; i++) {
    REQUIRE(i < MaxSlots) << "Too many sampled threads";
    thread_state* expected = nullptr;
    if(slots[i].compare_exchange_strong(expected, owner)) break;
  }
  slot = i;

  size_t hw = high_water.load();
  while(hw < i + 1 && !high_water.compare_exchange_weak(hw, i + 1)) {}
}

void perf_event::close() {
  if(!active.exchange(false)) return;

  // The sampler may be suspending this thread right now. Wait until it lets go
  while(busy.load()) YieldProcessor();

  slots[slot].store(nullptr);
  CloseHandle(h);
  CloseHandle(wake);
  h = wake = nullptr;
  VirtualFree(_ring, 0, MEM_RELEASE);
  _ring = nullptr;
}

void NTAPI coz_apc(ULONG_PTR);

namespace {
  typedef perf_event::sample_data sample_data;

  /// Code of one loaded module, as seen by the unwinder
  struct module_info {
    uint64_t base;
    uint64_t end;
    const RUNTIME_FUNCTION* functions;  //< Straight into the mapped .pdata, sorted by address
    uint32_t count;
  };

  /// Immutable once published, so the sampler reads it without locking
  struct module_table {
    std::vector<module_info> modules;
  };

  /// The part of LDR_DLL_NOTIFICATION_DATA that is used. Loaded and unloaded share this layout
  struct ldr_notification {
    ULONG flags;
    const void* full_name;
    const void* base_name;
    PVOID dll_base;
    ULONG image_size;
  };

  const ULONG LdrLoaded = 1;
  const ULONG LdrUnloaded = 2;
  const ULONG SpecialUserApc = 1;  //< QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC

  std::atomic<module_table*> g_modules{nullptr};
  spinlock g_modules_lock;  //< Serializes publishers. Old tables are leaked: the sampler may be reading one

  std::atomic<bool> g_run{false};
  HANDLE g_sampler = nullptr;
  std::atomic<bool> g_pay{false};  //< Set with g_pay_event, which wakes the sampler for a payment visit
  HANDLE g_pay_event = nullptr;

  /// Guest code, outside every loaded module, cannot take the APC: a payment visit leaves such a thread
  /// suspended, and the pauser thread resumes it when its debt is paid. One batch at a time, so that
  /// all the threads of a visit pay together
  struct hold { thread_state* state; size_t since, until; };
  hold g_holds[64];
  size_t g_nholds = 0;
  std::atomic<bool> g_holding{false};  //< The pauser owns g_holds until it clears this
  HANDLE g_pauser_event = nullptr;     //< Wakes the pauser for a new delay or batch
  std::atomic<bool> g_rescan{false};   //< Set with g_pauser_event: a new deadline may come first
  uint64_t g_cycles_per_period = 0;  //< Thread cycles that make one SamplePeriod of CPU time
  BOOL (WINAPI* g_queue_apc2)(PAPCFUNC, HANDLE, ULONG_PTR, ULONG) = nullptr;

  // Written by the sampler thread only, read after it is joined
  uint64_t g_samples_pushed = 0, g_samples_dropped = 0, g_apcs_queued = 0;

  /// Add and remove modules from the unwind cache
  void update_modules(const HMODULE* added, size_t count, HMODULE removed) {
    g_modules_lock.lock();

    module_table* next = new module_table();
    if(module_table* old = g_modules.load()) {
      for(const module_info& m : old->modules) {
        if(m.base != reinterpret_cast<uint64_t>(removed)) next->modules.push_back(m);
      }
    }

    for(size_t i = 0; i < count; i++) {
      uint64_t base = reinterpret_cast<uint64_t>(added[i]);
      bool known = false;
      for(const module_info& m : next->modules) known |= (m.base == base);
      if(known) continue;

      auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
      auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
      const IMAGE_DATA_DIRECTORY& pdata = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
      next->modules.push_back(module_info{
        base, base + nt->OptionalHeader.SizeOfImage,
        pdata.VirtualAddress ? reinterpret_cast<const RUNTIME_FUNCTION*>(base + pdata.VirtualAddress) : nullptr,
        (uint32_t)(pdata.Size / sizeof(RUNTIME_FUNCTION))});
    }

    std::sort(next->modules.begin(), next->modules.end(),
              [](const module_info& a, const module_info& b) { return a.base < b.base; });
    g_modules.store(next);
    g_modules_lock.unlock();
  }

  /// Runs under the loader lock: only builds and publishes a table
  VOID NTAPI on_dll_notification(ULONG reason, const ldr_notification* data, PVOID) {
    HMODULE module = static_cast<HMODULE>(data->dll_base);
    if(reason == LdrLoaded) update_modules(&module, 1, nullptr);
    else if(reason == LdrUnloaded) update_modules(nullptr, 0, module);
  }

  const module_info* find_module(const module_info* modules, size_t count, uint64_t pc) {
    size_t lo = 0, hi = count;
    while(lo < hi) {
      size_t mid = (lo + hi) / 2;
      if(modules[mid].base > pc) hi = mid;
      else lo = mid + 1;
    }
    return (lo > 0 && pc < modules[lo - 1].end) ? &modules[lo - 1] : nullptr;
  }

  const RUNTIME_FUNCTION* find_function(const module_info& m, uint64_t pc) {
    uint32_t rva = (uint32_t)(pc - m.base);
    size_t lo = 0, hi = m.count;
    while(lo < hi) {
      size_t mid = (lo + hi) / 2;
      if(m.functions[mid].BeginAddress > rva) hi = mid;
      else lo = mid + 1;
    }
    return (lo > 0 && rva < m.functions[lo - 1].EndAddress) ? &m.functions[lo - 1] : nullptr;
  }

  /// Unwind the stack of a suspended thread. The thread may hold any lock, so this only reads
  /// memory and calls RtlVirtualUnwind: no heap, no locks, no RtlLookupFunctionEntry, no DbgHelp.
  /// A memory read that faults just ends the walk
  __declspec(noinline) void walk_stack(CONTEXT* ctx, const NT_TIB* tib, const module_info* modules, size_t count,
                  sample_data* out, bool* in_syscall) {
    __try {
      // The thread is blocked in the kernel if it stopped right after a syscall instruction.
      // This is what exclude_kernel does for perf
      *in_syscall = *reinterpret_cast<const volatile uint16_t*>(ctx->Rip - 2) == 0x050F;
      if(*in_syscall) return;

      // The stack limits change under a fiber, so they are read at every sample
      uint64_t low = reinterpret_cast<uint64_t>(tib->StackLimit);
      uint64_t high = reinterpret_cast<uint64_t>(tib->StackBase);

      for(uint32_t depth = 0; out->n < perf_event::MaxFrames; depth++) {
        if(ctx->Rip == 0 || ctx->Rsp < low || ctx->Rsp >= high) break;

        // A return address points past the call, which may already be in another function
        uint64_t pc = depth == 0 ? ctx->Rip : ctx->Rip - 1;
        const module_info* m = find_module(modules, count, pc);
        if(m == nullptr) break;

        const RUNTIME_FUNCTION* f = find_function(*m, pc);
        if(f != nullptr) {
          PVOID handler_data;
          DWORD64 establisher;
          RtlVirtualUnwind(UNW_FLAG_NHANDLER, m->base, ctx->Rip, const_cast<PRUNTIME_FUNCTION>(f), ctx,
                           &handler_data, &establisher, nullptr);
        } else if(depth == 0) {
          // Leaf functions have no unwind data: the return address is on top of the stack
          ctx->Rip = *reinterpret_cast<const uint64_t*>(ctx->Rsp);
          ctx->Rsp += 8;
        } else {
          // A caller is never a leaf, so missing unwind data means the walk went wrong
          break;
        }

        if(ctx->Rip == 0) break;
        out->frames[out->n++] = ctx->Rip;
      }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }
  }

  /// Stop one thread and record where it is. On success the thread is left suspended
  bool capture(perf_event& s, const module_table* table, sample_data& out, bool& in_syscall, bool& in_module) {
    if(SuspendThread(s.h) == (DWORD)-1) return false;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if(!GetThreadContext(s.h, &ctx)) {  // Also waits for the suspension to complete
      ResumeThread(s.h);
      return false;
    }

    const module_info* modules = table ? table->modules.data() : nullptr;
    size_t count = table ? table->modules.size() : 0;
    in_module = find_module(modules, count, ctx.Rip) != nullptr;
    out.ip = ctx.Rip;
    out.tid = s.tid;
    out.n = 0;
    in_syscall = false;
    walk_stack(&ctx, s.teb, modules, count, &out, &in_syscall);
    return true;
  }

  /// Run f on every registered thread. Pairs with close(): either it sees busy, or this sees that the thread is going away
  template<class F> void for_each_thread(F f) {
    for(size_t i = 0, high = perf_event::high_water.load(); i < high; i++) {
      thread_state* state = perf_event::slots[i].load();
      if(state == nullptr || !state->sampler.active.load()) continue;
      state->sampler.busy.store(true);
      if(state->sampler.active.load()) f(state, state->sampler);
      state->sampler.busy.store(false);
    }
  }

  /// Visit every registered thread once. A thread seen running is sampled. tick: the visit is the periodic one
  void sample_all(const module_table* table, bool tick) {
    sample_data sample;
    static size_t visits = 0;
    const bool sweep = tick && ++visits % SampleBatchSize == 0;

    // Every SampleBatchSize visits the samples that the threads have not counted themselves are counted here, and
    // after any raise of the global delay all the threads seen running pay together. Counted and paid by each
    // thread apart, a thread that spins on another one's work waited through that one's pause and then paid its
    // own (FATO: a null line slowed a spin-joined job by 23%)
    bool pay = g_pay.exchange(false);
    const bool can_hold = !g_holding.load();
    if(sweep) for_each_thread([&](thread_state* state, perf_event&) { pay |= profiler::get_instance().count_samples(state); });

    for_each_thread([&](thread_state* state, perf_event& s) {
      // A thread seen running user code is sampled where it is, weighted by the time since its last
      // visit; seen blocked, in a syscall or in a delay, it is not. Crediting CPU time and paying
      // it at a later visit moved the samples of a thread that blocks and wakes toward wherever it
      // was seen next (FATO: a job run right after waking got half of its samples). Only the periodic
      // visits sample: a payment visit follows a raise by a thread, and finds it inside coz
      bool ran = true;
      size_t span = 0;
      if(tick) {
        ULONG64 cycles;
        if(!QueryThreadCycleTime(s.h, &cycles)) return;
        size_t now = get_time();
        span = now - s.last_visit;
        ran = cycles - s.last_cycles > g_cycles_per_period / 100;
        s.last_cycles = cycles, s.last_visit = now;
      }

      // The thread pays its delays through an APC. Nothing is queued to a blocked thread,
      // one in an alertable sleep that the APC would cut short, or while the last APC has not run.
      // A special APC writes its frame right below RSP (FATO), which would destroy the red
      // zone of SysV code such as a PS4 game's, so it is queued only while the thread is
      // stopped inside a loaded module: it then runs right there, when the thread resumes
      const bool apc = pay && !state->is_blocked.load() && !s.no_apc.load();
      bool in_syscall = false, in_module = false;
      if(!s.enabled.load() || !ran || !(tick || apc) || !capture(s, table, sample, in_syscall, in_module)) return;

      if(tick && !in_syscall) {
        // A full ring drops the sample
        perf_event::ring* r = s._ring;
        uint32_t write = r->write_idx.load(std::memory_order_relaxed);
        uint32_t read = r->read_idx.load(std::memory_order_acquire);
        if(write - read < perf_event::RingSize) {
          sample.weight = std::min<size_t>(span, SampleBatchSize * SamplePeriod);
          memcpy(&r->samples[write % perf_event::RingSize], &sample, offsetof(sample_data, frames) + sample.n * sizeof(uint64_t));
          r->write_idx.store(write + 1, std::memory_order_release);
          g_samples_pushed++;
        } else {
          g_samples_dropped++;
        }
      }

      if(apc && in_module && !s.apc_pending.exchange(true)) {
        if(g_queue_apc2(coz_apc, s.h, 0, SpecialUserApc)) g_apcs_queued++;
        else s.apc_pending.store(false);
      }
      size_t debt = apc && !in_module && !in_syscall && can_hold && g_nholds < 64 ? profiler::get_instance().debt(state) : 0;
      if(debt) {
        size_t now = get_time();
        g_holds[g_nholds++] = hold{state, now, now + debt};
      } else {
        ResumeThread(s.h);
      }
    });

    if(can_hold && g_nholds) {
      std::sort(g_holds, g_holds + g_nholds, [](const hold& a, const hold& b) { return a.until < b.until; });
      g_holding.store(true);
      g_rescan.store(true);
      real::NtSetEvent(g_pauser_event, nullptr);
    }
  }

  /// Ends every delay at its deadline: it wakes the threads sleeping in wait(), and resumes the held
  /// threads, crediting each with the time it really stood still. It is the only thread that spins,
  /// and only right before a deadline
  DWORD WINAPI pauser_main(LPVOID) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    HANDLE wake[2] = {g_pauser_event, timer};
    size_t resumed = 0;  //< Threads of the held batch already resumed
    for(;;) {
      size_t now = get_time(), next = SIZE_MAX;
      for(size_t i = 0, high = perf_event::high_water.load(); i < high; i++) {
        thread_state* state = perf_event::slots[i].load();
        size_t at = state != nullptr ? state->sampler.wake_at.load() : 0;
        if(at != 0 && at <= now) {
          state->sampler.wake_at.store(0);
          real::NtSetEvent(state->sampler.wake, nullptr);
        } else if(at != 0) {
          next = std::min(next, at);
        }
      }
      if(g_holding.load()) {
        for(; resumed < g_nholds && g_holds[resumed].until <= now; resumed++) {
          ResumeThread(g_holds[resumed].state->sampler.h);
          profiler::get_instance().paid(g_holds[resumed].state, get_time() - g_holds[resumed].since);
        }
        if(resumed < g_nholds) {
          next = std::min(next, g_holds[resumed].until);
        } else {
          resumed = g_nholds = 0;
          g_holding.store(false);
        }
      }

      // Sleep while the next deadline is far, waking for a new one, then spin to it
      if(next == SIZE_MAX) {
        real::NtWaitForSingleObject(g_pauser_event, FALSE, NULL);
      } else if(next > now + g_spin_ns) {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)((next - now - g_spin_ns) / 100);
        SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
        real::NtWaitForMultipleObjects(2, wake, 1 /* WaitAny */, FALSE, NULL);
      } else {
        while(get_time() < next && !g_rescan.load()) YieldProcessor();
        g_rescan.store(false);
      }
    }
  }

  DWORD WINAPI sampler_main(LPVOID) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    HANDLE wake[2] = {timer, g_pay_event};

    // A payment visit leaves the timer running: re-armed from there, the samples fell at a fixed time
    // after a raise, so always in the same phase of a frame (FATO: a serial line lost 30% of its hits)
    for(bool tick = true; g_run.load();) {
      LARGE_INTEGER due;
      due.QuadPart = -(SamplePeriod / 100);
      if(tick) SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
      tick = real::NtWaitForMultipleObjects(2, wake, 1 /* WaitAny */, FALSE, NULL) == 0;
      sample_all(g_modules.load(), tick);
    }

    CloseHandle(timer);
    return 0;
  }

  /// Thread cycles per SamplePeriod. The best of several runs: preemption and warm-up only lower it
  uint64_t measure_cycles_per_period() {
    double best = 0;
    for(int run = 0; run < 5; run++) {
      ULONG64 c0, c1;
      QueryThreadCycleTime(GetCurrentThread(), &c0);
      size_t t0 = get_time(), t1;
      while((t1 = get_time()) - t0 < 20 * 1000 * 1000) {}
      QueryThreadCycleTime(GetCurrentThread(), &c1);
      best = std::max(best, (double)(c1 - c0) / (double)(t1 - t0));
    }
    return (uint64_t)(best * SamplePeriod);
  }

  /// How long wait() has to spin: the p99 overshoot of the high-resolution timer
  size_t measure_spin_ns() {
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    std::vector<size_t> overshoot;
    for(int i = 0; i < 200; i++) {
      LARGE_INTEGER due;
      due.QuadPart = -(1000 * 1000 / 100);
      size_t start = get_time();
      SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
      real::NtWaitForSingleObject(timer, FALSE, NULL);
      size_t elapsed = get_time() - start;
      overshoot.push_back(elapsed > 1000 * 1000 ? elapsed - 1000 * 1000 : 0);
    }
    CloseHandle(timer);

    std::sort(overshoot.begin(), overshoot.end());
    return std::min<size_t>(std::max<size_t>(overshoot[overshoot.size() * 99 / 100], 500 * 1000), 2000 * 1000);
  }
}

/// Runs on the sampled thread itself, ahead of its own code
void NTAPI coz_apc(ULONG_PTR) {
  DWORD error = GetLastError();
  profiler::get_instance().apc_samples_ready();
  SetLastError(error);
}

void win_sampler_start() {
  g_queue_apc2 = reinterpret_cast<decltype(g_queue_apc2)>(
    GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueueUserAPC2"));
  REQUIRE(g_queue_apc2 != nullptr) << "coz needs QueueUserAPC2: Windows 11 (build 22000) or Windows Server 2022";

  // Done here, before any thread can call wait()
  g_cycles_per_period = measure_cycles_per_period();
  g_spin_ns = measure_spin_ns();
  VERBOSE << "cycles per sample period: " << g_cycles_per_period << ", wait() spin: " << g_spin_ns << " ns";

  // The unwinder follows modules as they are loaded. Register first, so none is missed
  PVOID cookie;
  auto register_notification = reinterpret_cast<LONG (NTAPI*)(ULONG, PVOID, PVOID, PVOID*)>(
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"));
  REQUIRE(register_notification != nullptr) << "LdrRegisterDllNotification is not available";
  register_notification(0, reinterpret_cast<PVOID>(on_dll_notification), nullptr, &cookie);

  // EnumProcessModulesEx takes the loader lock, which a notification may hold while it waits for
  // g_modules_lock. So the list is built before taking that lock
  std::vector<HMODULE> modules(1024);
  DWORD needed = 0;
  if(EnumProcessModulesEx(GetCurrentProcess(), modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)),
                          &needed, LIST_MODULES_ALL)) {
    modules.resize(std::min<size_t>(modules.size(), needed / sizeof(HMODULE)));
    update_modules(modules.data(), modules.size(), nullptr);
  }

  g_pay_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  g_pauser_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  g_run.store(true);
  // The pauser runs until the process ends: a thread may pay a delay at any time
  HANDLE pauser = win_create_internal_thread(pauser_main, nullptr);
  g_sampler = win_create_internal_thread(sampler_main, nullptr);
  REQUIRE(g_sampler != nullptr && pauser != nullptr) << "Failed to start the sampler threads";
  CloseHandle(pauser);
}

bool win_pause_until(size_t deadline) {
  thread_state* state = static_cast<thread_state*>(TlsGetValue(g_tls));
  if(state == nullptr || !state->sampler.active.load()) return false;

  // Woken this early, the thread spins only the last stretch. Woken at the deadline, the latency of
  // the wake ran over every delay, even a tiny one, and the excess fed back into the delay counts
  // without end (FATO: 27% of the time in delays at 0% speedup)
  const size_t lead = 150 * 1000;
  if(deadline > get_time() + lead) {
    state->sampler.wake_at.store(deadline - lead);
    g_rescan.store(true);
    real::NtSetEvent(g_pauser_event, nullptr);
    real::NtWaitForSingleObject(state->sampler.wake, FALSE, NULL);
  }
  while(get_time() < deadline) YieldProcessor();
  return true;
}

void win_sampler_pay() {
  if(!g_pay.exchange(true)) real::NtSetEvent(g_pay_event, nullptr);
}

void win_sampler_stop() {
  if(g_sampler == nullptr) return;

  g_run.store(false);
  real::NtWaitForSingleObject(g_sampler, FALSE, NULL);
  CloseHandle(g_sampler);
  g_sampler = nullptr;

  VERBOSE << "sampler: " << g_samples_pushed << " samples, " << g_samples_dropped
          << " dropped (ring full), " << g_apcs_queued << " APCs";
}
