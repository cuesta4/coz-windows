/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include "perf.h"

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
  acc = 0;
  since_apc = 0;
  enabled.store(false);
  busy.store(false);
  apc_pending.store(false);
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
  h = nullptr;
  VirtualFree(_ring, 0, MEM_RELEASE);
  _ring = nullptr;
}
