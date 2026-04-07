#pragma once

#include "nalt.hpp"
#include "pro.h"

#include "cxx.h"

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    return rust::String(path, size);
  } else {
    return rust::String();
  }
}

// ---------------------------------------------------------------------------
// Import enumeration wrappers
//
// IDA stores imports per-module (e.g. kernel32.dll, ntdll.dll).
// We enumerate modules, then enumerate names within each module,
// and return them as a single newline-delimited string:
//   "module_name\tea\tfunction_name\n..."
// ---------------------------------------------------------------------------

/// Return the number of import modules.
uint32_t idalib_get_import_module_qty() {
  return (uint32_t)get_import_module_qty();
}

/// Get the name of import module at `mod_index`.
rust::String idalib_get_import_module_name(uint32_t mod_index) {
  qstring buf;
  if (get_import_module_name(&buf, (int)mod_index)) {
    return rust::String(buf.c_str(), buf.length());
  }
  return rust::String();
}

struct ImportCollector {
  qstring result;
  const char *module_name;
};

static int idaapi collect_import_cb(ea_t ea, const char *name, uval_t ord, void *param) {
  ImportCollector *coll = (ImportCollector *)param;
  // Format: module\tea\tname\n
  coll->result.cat_sprnt("%s\t0x%llx\t%s\n",
    coll->module_name,
    (unsigned long long)ea,
    name ? name : "");
  return 1; // continue
}

/// Enumerate ALL imports across ALL modules.
/// Returns a string with one import per line: "module\t0xADDR\tname\n"
rust::String idalib_enum_all_imports() {
  ImportCollector coll;
  coll.result.reserve(8192);

  int nmod = get_import_module_qty();
  for (int i = 0; i < nmod; i++) {
    qstring mod_name;
    if (get_import_module_name(&mod_name, i)) {
      coll.module_name = mod_name.c_str();
    } else {
      coll.module_name = "";
    }
    enum_import_names(i, collect_import_cb, &coll);
  }

  return rust::String(coll.result.c_str(), coll.result.length());
}
