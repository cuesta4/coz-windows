/*
 * Copyright (c) 2015, Charlie Curtsinger and Emery Berger,
 *                     University of Massachusetts Amherst
 * This file is part of the Coz project. See LICENSE.md file at the top-level
 * directory of this distribution and at http://github.com/plasma-umass/coz.
 */

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

#include <detours.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
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

  /// Find the innermost frame of an inlined address that is in scope. The chain ends with the
  /// function that contains the address, at the line of its own line table
  bool in_scope_inline_frame(HANDLE proc, line_context& c, uint64_t address, DWORD frames,
                             uint32_t& file, size_t& line) {
    DWORD context, index;
    if(!SymQueryInlineTrace(proc, address, 0, address, address, &context, &index))
      return false;

    for(DWORD k = 0; k <= frames; k++) {
      IMAGEHLP_LINEW64 info;
      info.SizeOfStruct = sizeof(info);
      DWORD displacement;
      if(!SymGetLineFromInlineContextW(proc, address, context + k, 0, &displacement, &info) ||
         info.LineNumber == 0xFEEFEE || info.LineNumber == 0xF00F00)
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

  /// A range of a source line, relative to the module base
  struct cached_range {
    uint32_t file, line, low, high;
  };

  /// The cache holds the file names, then the ranges, each set after its count
  bool read_cache(const wstring& path, vector<string>& names, vector<cached_range>& ranges) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if(f == nullptr) return false;
    uint32_t files = 0;
    uint64_t count = 0;
    bool ok = fread(&files, sizeof(files), 1, f) == 1;
    for(uint32_t i = 0; ok && i < files; i++) {
      uint32_t size = 0;
      ok = fread(&size, sizeof(size), 1, f) == 1 && size < 65536;
      names.emplace_back(ok ? size : 0, '\0');
      ok = ok && fread(&names.back()[0], 1, size, f) == size;
    }
    ok = ok && fread(&count, sizeof(count), 1, f) == 1 && count < (1ull << 32);
    if(ok) ranges.resize(count);
    ok = ok && fread(ranges.data(), sizeof(cached_range), count, f) == count;
    fclose(f);
    for(const cached_range& r : ranges) ok = ok && r.file < names.size();
    return ok;
  }

  void write_cache(const wstring& path, const vector<string>& names, const vector<cached_range>& ranges) {
    wstring partial = path + L".part";
    FILE* f = _wfopen(partial.c_str(), L"wb");
    if(f == nullptr) return;
    uint32_t files = (uint32_t)names.size();
    uint64_t count = ranges.size();
    bool ok = fwrite(&files, sizeof(files), 1, f) == 1;
    for(const string& name : names) {
      uint32_t size = (uint32_t)name.size();
      ok = ok && fwrite(&size, sizeof(size), 1, f) == 1 && fwrite(name.data(), 1, size, f) == size;
    }
    ok = ok && fwrite(&count, sizeof(count), 1, f) == 1 && fwrite(ranges.data(), sizeof(cached_range), count, f) == count;
    ok = fclose(f) == 0 && ok;
    if(!ok || !MoveFileExW(partial.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) DeleteFileW(partial.c_str());
  }
}

/// The line ranges of a module whose symbols are loaded at its real base
static void build_ranges(HANDLE proc, DWORD64 base, const unordered_set<string>& source_scope,
                         bool allow_system_sources, vector<string>& names, vector<cached_range>& ranges) {
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

  for(size_t i = 0; i < records.size(); i++) {
    uint64_t address = records[i].address;
    auto f = upper_bound(functions.begin(), functions.end(), function_range{address, UINT64_MAX});
    if(f == functions.begin() || address >= (--f)->high)
      continue;

    uint64_t limit = f->high;
    if(i + 1 < records.size())
      limit = min(limit, records[i + 1].address);

    // The PDB line table gives inlined code the line of its outermost call site, while the DWARF
    // line table on Linux gives the inlinee's own lines. So inlined instructions take the innermost
    // in-scope frame of their inline chain, which also covers out-of-scope code such as a user
    // lambda inlined into a library function. Runs of instructions with the same line become ranges
    const uint32_t none = UINT32_MAX;
    uint64_t run = address;
    uint32_t run_file = none;
    size_t run_line = 0;
    for(uint64_t x = address; x <= limit;) {
      uint32_t file = records[i].file;
      size_t line = records[i].line;
      if(x < limit) {
        DWORD frames = SymAddrIncludeInlineTrace(proc, x);
        bool ok = frames > 0 ? in_scope_inline_frame(proc, context, x, frames, file, line)
                             : context.files[file].in_scope;
        if(!ok) file = none;
      }

      if(x == limit || file != run_file || line != run_line) {
        if(run_file != none && x > run)
          ranges.push_back(cached_range{run_file, (uint32_t)run_line, (uint32_t)(run - base), (uint32_t)(x - base)});
        run = x;
        run_file = file;
        run_line = line;
      }
      if(x == limit) break;

      // Step one instruction. Bytes that do not decode end the splitting of this record
      uint64_t next = (uint64_t)DetourCopyInstruction(nullptr, nullptr, (PVOID)x, nullptr, nullptr);
      x = (next > x && next <= limit) ? next : limit;
    }
  }

  for(const source_file& f : context.files) names.push_back(f.name);
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

  // The pass over the instructions below takes minutes on a large program (FATO: 131 s on GOW3, nearly all in
  // DbgHelp's inline lookups), and its ranges depend only on the PDB and the scope: they are kept in the temp
  // directory, under a hash of both
  uint64_t key = 14695981039346656037ull;
  auto mix = [&key](const void* p, size_t n) {
    for(size_t i = 0; i < n; i++) key = (key ^ static_cast<const uint8_t*>(p)[i]) * 1099511628211ull;
  };
  mix("coz-lines-1", 11);
  mix(&module.PdbSig70, sizeof(module.PdbSig70));
  mix(&module.PdbAge, sizeof(module.PdbAge));
  mix(&allow_system_sources, sizeof(allow_system_sources));
  for(const string& s : set<string>(source_scope.begin(), source_scope.end())) mix(s.c_str(), s.size() + 1);
  wchar_t temp[MAX_PATH + 1], file[32];
  swprintf(file, 32, L"coz-%016llx.lines", (unsigned long long)key);
  wstring cache = wstring(temp, GetTempPathW(MAX_PATH + 1, temp)) + file;

  vector<string> names;
  vector<cached_range> ranges;
  if(read_cache(cache, names, ranges)) {
    VERBOSE << "Line ranges of " << name << " read from the cache";
  } else {
    names.clear();
    ranges.clear();
    build_ranges(proc, base, source_scope, allow_system_sources, names, ranges);
    write_cache(cache, names, ranges);
  }

  set<string> included_files;
  for(const cached_range& r : ranges) {
    included_files.insert(names[r.file]);
    add_range(names[r.file], r.line, interval((uintptr_t)(base + r.low), (uintptr_t)(base + r.high)));
  }
  for(const string& filename : included_files) {
    VERBOSE << "Included source file " << filename;
  }

  SymUnloadModule64(proc, base);
  return true;
}
