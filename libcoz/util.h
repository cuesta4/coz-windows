/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#if !defined(CAUSAL_RUNTIME_UTIL_H)
#define CAUSAL_RUNTIME_UTIL_H

#if defined(__APPLE__)
#include <mach/mach_time.h>
#elif defined(_WIN32)
#include <windows.h>
#include <stdlib.h>
#else
#include <time.h>
#endif

#ifndef _WIN32
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include "win_hooks.h"
#else
#include "real.h"
#endif

/**
 * Get the current time in nanoseconds
 */
static size_t get_time() {
#if defined(__APPLE__)
  // Convert mach_absolute_time ticks to nanoseconds using timebase info.
  // This ensures consistent units with _global_delay (nanoseconds) and
  // nanosleep-based wait() calls.
  static mach_timebase_info_data_t timebase = {0, 0};
  if (timebase.denom == 0) {
    mach_timebase_info(&timebase);
  }
  return (mach_absolute_time() * timebase.numer) / timebase.denom;
#elif defined(_WIN32)
  // Split the conversion so that ticks * 1e9 cannot overflow
  LARGE_INTEGER ticks, freq;
  QueryPerformanceCounter(&ticks);
  QueryPerformanceFrequency(&freq);
  return ticks.QuadPart / freq.QuadPart * 1000000000ull +
         ticks.QuadPart % freq.QuadPart * 1000000000ull / freq.QuadPart;
#else
  struct timespec ts;
  if(clock_gettime(CLOCK_REALTIME, &ts)) {
    perror("get_time():");
    abort();
  }
  return ts.tv_nsec + ts.tv_sec * 1000 * 1000 * 1000;
#endif
}

#ifdef _WIN32
/// Sleep on the thread's high-resolution timer, then spin to the deadline. The timer
/// alone overshoots by up to a millisecond, which would feed back into the delay counts.
static inline size_t wait(size_t ns) {
  if(ns == 0) return 0;

  size_t start_time = get_time();
  size_t deadline = start_time + ns;

  if(ns > g_spin_ns) {
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)((ns - g_spin_ns) / 100);
    HANDLE timer = win_wait_timer();
    SetWaitableTimer(timer, &due, 0, NULL, NULL, FALSE);
    real::NtWaitForSingleObject(timer, FALSE, NULL);
  }

  for(size_t now = get_time(); now < deadline; now = get_time()) {
    if(deadline - now > 20000) SwitchToThread();
    else YieldProcessor();
  }

  return get_time() - start_time;
}
#else
static inline size_t wait(size_t ns) {
  if(ns == 0) return 0;

  struct timespec ts;
  ts.tv_nsec = ns % (1000 * 1000 * 1000);
  ts.tv_sec = (ns - ts.tv_nsec) / (1000 * 1000 * 1000);

  size_t start_time = get_time();
  while(nanosleep(&ts, &ts) != 0) {}

  return get_time() - start_time;
}
#endif

static inline std::vector<std::string> split(const std::string& s, char delim='\t') {
  std::vector<std::string> elems;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if(item.length()) elems.push_back(item);
  }
  return elems;
}

static inline std::string getenv_safe(const char* var, const char* fallback = "") {
  const char* value = getenv(var);
  if(!value) value = fallback;
  return std::string(value);
}

#endif
