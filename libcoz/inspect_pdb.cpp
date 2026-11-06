/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "inspect.h"

#include "ccutil/log.h"

using namespace std;

static wstring to_wide(const string& s) {
  int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
  wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
  return w;
}

static string to_utf8(const wchar_t* w) {
  int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
  string s(n > 0 ? n - 1 : 0, '\0');
  if(n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, NULL, NULL);
  return s;
}

string canonicalize_path(const string& filename) {
  // A name that is not a valid path is kept as it is, like the POSIX version does
  wstring w = to_wide(filename);
  DWORD n = GetFullPathNameW(w.c_str(), 0, NULL, NULL);
  string result = filename;
  if(n > 0) {
    wstring full(n, L'\0');
    full.resize(GetFullPathNameW(w.c_str(), n, &full[0], NULL));
    result = to_utf8(full.c_str());
  }
  replace(result.begin(), result.end(), '\\', '/');
  if(result.size() > 1 && result[1] == ':')
    result[0] = (char)toupper((unsigned char)result[0]);
  return result;
}

string main_executable_path() {
  wchar_t path[4096];
  return GetModuleFileNameW(NULL, path, 4096) > 0 ? canonicalize_path(to_utf8(path)) : string();
}

/// Map each loaded module's path to its base address
unordered_map<string, uintptr_t> get_loaded_files() {
  unordered_map<string, uintptr_t> result;

  vector<HMODULE> modules(1024);
  DWORD needed = 0;
  if(!EnumProcessModulesEx(GetCurrentProcess(), modules.data(),
                           (DWORD)(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL))
    return result;
  modules.resize(min<size_t>(modules.size(), needed / sizeof(HMODULE)));

  for(HMODULE m : modules) {
    wchar_t path[4096];
    if(GetModuleFileNameW(m, path, 4096) > 0) {
      result[canonicalize_path(to_utf8(path))] = reinterpret_cast<uintptr_t>(m);
    }
  }

  return result;
}

namespace {
  struct source_file {
    string name;
    bool in_scope;
  };

  struct line_record {
    uint64_t address;
    uint32_t line;
    uint32_t file;  //< Index into line_context::files
  };

  struct function_range {
    uint64_t low;
    uint64_t high;
    bool operator<(const function_range& o) const {
      return low != o.low ? low < o.low : high < o.high;
    }
  };

  struct line_context {
    const unordered_set<string>& source_scope;
    bool allow_system_sources;
    vector<line_record> records;
    vector<source_file> files;
    unordered_map<wstring, uint32_t> file_index;
  };

  /// Index of a source file, canonicalized and checked against the scope only once
  uint32_t file_id(line_context& c, const wchar_t* path) {
    auto it = c.file_index.find(path);
    if(it == c.file_index.end()) {
      string name = canonicalize_path(to_utf8(path));
      bool ok = file_matches_scope(name, c.source_scope, c.allow_system_sources);
      it = c.file_index.emplace(path, (uint32_t)c.files.size()).first;
      c.files.push_back(source_file{name, ok});
    }
    return it->second;
  }

  BOOL CALLBACK on_line(PSRCCODEINFOW info, PVOID p) {
    auto* c = static_cast<line_context*>(p);

    // The compiler marks code that belongs to no source line with these line numbers
    if(info->LineNumber == 0xFEEFEE || info->LineNumber == 0xF00F00)
      return TRUE;

    c->records.push_back(line_record{info->Address, info->LineNumber, file_id(*c, info->FileName)});
    return TRUE;
  }

  BOOL CALLBACK on_symbol(PSYMBOL_INFOW sym, ULONG size, PVOID p) {
    // 5 is SymTagFunction (cvconst.h)
    if(sym->Tag == 5 && size > 0)
      static_cast<vector<function_range>*>(p)->push_back(function_range{sym->Address, sym->Address + size});
    return TRUE;
  }

  /// Find the innermost inlined frame of an address that is in scope
  bool in_scope_inline_frame(HANDLE proc, line_context& c, uint64_t address, uint32_t& file, size_t& line) {
    DWORD frames = SymAddrIncludeInlineTrace(proc, address);
    DWORD context, index;
    if(frames == 0 || !SymQueryInlineTrace(proc, address, 0, address, address, &context, &index))
      return false;

    for(DWORD k = 0; k <= frames; k++) {
      IMAGEHLP_LINEW64 info;
      info.SizeOfStruct = sizeof(info);
      DWORD displacement;
      if(!SymGetLineFromInlineContextW(proc, address, context + k, 0, &displacement, &info))
        continue;

      uint32_t id = file_id(c, info.FileName);
      if(c.files[id].in_scope) {
        file = id;
        line = info.LineNumber;
        return true;
      }
    }

    return false;
  }
}

bool memory_map::process_file(const string& name, uintptr_t load_address,
                              const unordered_set<string>& source_scope,
                              bool allow_system_sources) {
  // DbgHelp is not thread safe. It is only used here, on the thread that builds the map
  HANDLE proc = GetCurrentProcess();
  static bool initialized = false;
  if(!initialized) {
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_UNDNAME);
    initialized = SymInitializeW(proc, NULL, FALSE);
    if(!initialized) return false;
  }

  // The PDB is found next to the module through its CodeView record: no symbol path needed
  wstring path = to_wide(name);
  replace(path.begin(), path.end(), L'/', L'\\');
  DWORD64 base = load_address;
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
  if(!SymLoadModuleExW(proc, NULL, path.c_str(), NULL, base, nt->OptionalHeader.SizeOfImage, NULL, 0))
    return false;

  IMAGEHLP_MODULEW64 module;
  module.SizeOfStruct = sizeof(module);
  if(!SymGetModuleInfoW64(proc, base, &module) || module.SymType != SymPdb || !module.LineNumbers) {
    SymUnloadModule64(proc, base);
    return false;
  }

  // Addresses are absolute because the module was loaded at its real base
  line_context context{source_scope, allow_system_sources, {}, {}, {}};
  SymEnumLinesW(proc, base, NULL, NULL, on_line, &context);

  // Line records come in no particular order, and several can share an address (prologue
  // lines). Keep the last one of each address, as the DWARF line table does
  stable_sort(context.records.begin(), context.records.end(),
              [](const line_record& a, const line_record& b) { return a.address < b.address; });
  vector<line_record> records;
  for(const line_record& r : context.records) {
    if(!records.empty() && records.back().address == r.address)
      records.back() = r;
    else
      records.push_back(r);
  }

  // A range ends at the next line record or the end of its function, whichever is first.
  // Leaf functions have no unwind data, so function bounds come from the symbols
  vector<function_range> functions;
  SymEnumSymbolsW(proc, base, L"*", on_symbol, &functions);
  sort(functions.begin(), functions.end());

  set<string> included_files;
  for(size_t i = 0; i < records.size(); i++) {
    uint64_t address = records[i].address;
    auto f = upper_bound(functions.begin(), functions.end(), function_range{address, UINT64_MAX});
    if(f == functions.begin() || address >= (--f)->high)
      continue;

    uint64_t limit = f->high;
    if(i + 1 < records.size())
      limit = min(limit, records[i + 1].address);

    // Code from an out-of-scope file, such as a user lambda inlined into a library
    // function, is attributed to the in-scope frame of its inline chain
    uint32_t file = records[i].file;
    size_t line = records[i].line;
    if(!context.files[file].in_scope && !in_scope_inline_frame(proc, context, address, file, line))
      continue;

    const string& name = context.files[file].name;
    included_files.insert(name);
    add_range(name, line, interval((uintptr_t)address, (uintptr_t)limit));
  }

  for(const string& filename : included_files) {
    VERBOSE << "Included source file " << filename;
  }

  SymUnloadModule64(proc, base);
  return true;
}
