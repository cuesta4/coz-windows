#if !defined(CCUTIL_LOG_H)
#define CCUTIL_LOG_H

#include <cstdlib>
#include <iostream>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace ccutil {
  // Check COZ_VERBOSE environment variable (cached for performance)
  inline bool is_verbose() {
    static int cached = -1;
    if (cached < 0) {
      const char* env = std::getenv("COZ_VERBOSE");
      cached = (env != nullptr && env[0] == '1') ? 1 : 0;
    }
    return cached == 1;
  }
#if defined(_WIN32)
  // Escapes are only emitted to a console that already interprets them. The console mode is
  // shared with the parent shell, so it is never changed here
  inline bool use_colors() {
    static const bool enabled = [] {
      DWORD mode;
      return GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode) && (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }();
    return enabled;
  }
#  define COZ_COLOR(name, code) inline const char* name() { return use_colors() ? code : ""; }
#else
#  define COZ_COLOR(name, code) inline const char* name() { return code; }
#endif
  COZ_COLOR(InfoColor, "\033[01;34m")
  COZ_COLOR(WarningColor, "\033[01;33m")
  COZ_COLOR(FatalColor, "\033[01;31m")
  COZ_COLOR(SourceColor, "\033[34m")
  COZ_COLOR(EndColor, "\033[0m")

  class logger_base {
  public:
    logger_base indent(size_t n, size_t tab_size = 2) {
      return logger_base();
    }
    
    template<typename T> logger_base  operator<<(T t) {
      return logger_base();
    }
  };

  class logger : public logger_base {
  private:
    bool _done;
    bool _exit;
  public:
    logger(bool exit = false, bool done = true) : _exit(exit), _done(done) {}
  
    logger(logger&& other) {
      _exit = other._exit;
      _done = other._done;
      other._done = false;
    }
  
    ~logger() {
      if(_done) {
        std::cerr << EndColor() << "\n";
        if(_exit) abort();
      }
    }
    
    void operator=(logger&& other) {
      _exit = other._exit;
      _done = other._done;
      other._done = false;
    }
    
    logger&& indent(size_t n, size_t tab_size = 2) {
      for(size_t i=0; i<n; i++) {
        for(size_t j=0; j<tab_size; j++) {
          std::cerr << " ";
        }
      }
      return std::move(*this);
    }
  
    template<typename T> logger&& operator<<(T t) {
      std::cerr << t;
      return std::move(*this);
    }
  };
}

#if defined(NDEBUG)
#  define LOG(color, exit) (ccutil::logger(exit) << color)
#  define INFO (ccutil::logger_base())
#  define ASSERT(cond) (ccutil::logger_base())
#else
#  define LOG(color, exit) (ccutil::logger(exit) << ccutil::SourceColor() << "[" << __FILE__ << ":" << __LINE__ << "] " << color)
#  define INFO LOG(ccutil::InfoColor(), false)
#  define ASSERT(cond) (cond) ? ccutil::logger_base() : FATAL
#endif

#define WARNING LOG(ccutil::WarningColor(), false)
#define PREFER(cond) (cond) ? ccutil::logger_base() : WARNING

#define FATAL LOG(ccutil::FatalColor(), true)
#define REQUIRE(cond) (cond) ? ccutil::logger_base() : FATAL

// VERBOSE: Runtime-controlled info output (enabled by COZ_VERBOSE=1 environment variable)
// Uses if-else pattern to avoid ternary type slicing (logger&& vs logger_base)
#define VERBOSE if (!ccutil::is_verbose()) {} else LOG(ccutil::InfoColor(), false)

#endif