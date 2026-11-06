/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#if !defined(CAUSAL_RUNTIME_THREAD_STATE_H)
#define CAUSAL_RUNTIME_THREAD_STATE_H

#include <atomic>

#ifdef _WIN32
#include <windows.h>
#else
#include "ccutil/timer.h"
#endif

class thread_state {
public:
  bool in_use = false;      //< Set by the main thread to prevent signal handler from racing
  std::atomic<size_t> local_delay{0};   //< The count of delays (or selected line visits) in the thread
  perf_event sampler;       //< The sampler object for this thread
#ifdef _WIN32
  bool in_hook = false;     //< Set while a sync hook runs, so nested hooked calls pass through
  size_t pre_block_local;   //< The local delay saved before (possibly) blocking
  std::atomic<size_t> d_own{0}, d_paid{0}, d_catch{0}, d_skip{0}, d_raise{0}, d_samples{0}, d_hits{0}, d_blk_s{0}, d_blk_p{0};  // TEMP-DIAG per experiment
  size_t d_t_block = 0, d_cyc_prev = 0;  // TEMP-DIAG
#else
  timer process_timer;      //< The timer that triggers sample processing for this thread
#endif
  size_t pre_block_time;    //< The time saved before (possibly) blocking
  std::atomic<bool> is_blocked{false};  //< True between pre_block() and post_block(); skip delays
  
  inline void set_in_use(bool value) {
    in_use = value;
    std::atomic_signal_fence(std::memory_order_seq_cst);
  }
  
  bool check_in_use() {
    return in_use;
  }
};

#endif
