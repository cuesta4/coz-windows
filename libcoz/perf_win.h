/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#if !defined(CAUSAL_RUNTIME_PERF_WIN_H)
#define CAUSAL_RUNTIME_PERF_WIN_H

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "ccutil/log.h"
#include "ccutil/wrapped_array.h"

class thread_state;

/// Windows sampler. The sampler thread credits each registered thread one sample per
/// SamplePeriod of its own CPU time and pushes it into the thread's ring. The thread
/// consumes its ring on its own stack, so the interface mirrors the Linux perf_event.
class perf_event {
public:
  enum { RingSize = 64, MaxFrames = 127, MaxSlots = 1024 };

  /// One sample: ip, tid and the return addresses of the callchain
  struct sample_data {
    uint64_t ip;
    uint32_t tid;
    uint32_t n;
    uint64_t frames[MaxFrames];
  };

  /// Single-producer (sampler thread), single-consumer (owning thread) ring
  struct ring {
    alignas(64) std::atomic<uint32_t> write_idx;
    alignas(64) std::atomic<uint32_t> read_idx;
    alignas(64) sample_data samples[RingSize];
  };

  class record {
  public:
    explicit record(sample_data* s) : _s(s) {}
    inline bool is_sample() const { return true; }
    inline uint64_t get_ip() const { return _s->ip; }
    inline uint64_t get_tid() const { return _s->tid; }
    inline ccutil::wrapped_array<uint64_t> get_callchain() const {
      return ccutil::wrapped_array<uint64_t>(_s->frames, _s->n);
    }
  private:
    sample_data* _s;
  };

  /// Walks the unread records and releases them back to the producer when destroyed
  class iterator {
  public:
    explicit iterator(ring* r) : _ring(r), _index(0), _head(0) {
      if(r != nullptr) {
        _index = r->read_idx.load(std::memory_order_relaxed);
        _head = r->write_idx.load(std::memory_order_acquire);
      }
    }

    ~iterator() {
      if(_ring != nullptr) _ring->read_idx.store(_index, std::memory_order_release);
    }

    inline bool has_data() const { return _ring != nullptr && _index != _head; }

    iterator& operator++() { _index++; return *this; }
    record operator*() { return record(&_ring->samples[_index % RingSize]); }
    bool operator!=(const iterator& other) { return has_data() != other.has_data(); }

  private:
    ring* _ring;
    uint32_t _index;
    uint32_t _head;
  };

  iterator begin() { return iterator(_ring); }
  iterator end() { return iterator(nullptr); }

  /// Register the calling thread with the sampler. The sampler stays idle until start()
  void open(thread_state* owner);

  /// Resume crediting samples
  void start() { enabled.store(true); }

  /// Stop crediting samples; the CPU time of a stopped period is discarded
  void stop() { enabled.store(false); }

  /// Unregister from the sampler and release the handle and ring
  void close();

  // Hot fields read and written by the sampler thread, kept contiguous
  HANDLE h = nullptr;                //< Handle to the sampled thread
  uint64_t last_cycles = 0;          //< Thread cycle count at the previous tick
  uint64_t acc = 0;                  //< CPU cycles credited but not yet turned into samples
  uint32_t since_apc = 0;            //< Samples pushed since the last processing APC
  std::atomic<bool> active{false};   //< Registered with the sampler
  std::atomic<bool> enabled{false};  //< start() was called and stop() was not
  std::atomic<bool> busy{false};     //< The sampler is touching this thread right now
  std::atomic<bool> apc_pending{false};  //< A processing APC is queued but has not run
  std::atomic<bool> no_apc{false};   //< The thread is in an alertable wait: do not queue APCs
  thread_state* state = nullptr;     //< Owner, for is_blocked
  NT_TIB* teb = nullptr;             //< Stack limits are read from here at sample time
  DWORD tid = 0;
  ring* _ring = nullptr;             //< Out of line: it would bloat every thread_state
  size_t slot = 0;                   //< Index in the dense registry

  /// Dense registry of active sampler slots, scanned by the sampler thread every tick
  static std::atomic<thread_state*> slots[MaxSlots];
  static std::atomic<size_t> high_water;  //< One past the highest slot ever used
};

/// Calibrate the sampler and start its thread. Threads that register later are picked up
void win_sampler_start();

/// Stop the sampler thread and wait for it. No sample or APC is produced afterwards
void win_sampler_stop();

#endif
