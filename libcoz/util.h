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
bool win_pause_until(size_t deadline);

/// Sleep until the pauser thread wakes the thread right before the deadline. Spun by every paused
/// thread, the end of a delay slowed the threads still running (FATO: a null line slowed GOW3 16%
/// with whole delays spun); slept on a timer, it ran over and the excess fed back into the delay
/// counts (FATO: 65% of the time in delays at 0% speedup)
static inline size_t wait(size_t ns) {
  if(ns == 0) return 0;

  size_t start_time = get_time();

  // coz's own threads need no precision. They only sleep, and shutdown ends the sleep, so an
  // experiment does not count the time after the program's last progress
  if(!win_pause_until(start_time + ns)) {
    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)(ns / 100);
    real::NtWaitForSingleObject(g_stop, FALSE, &due);
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
