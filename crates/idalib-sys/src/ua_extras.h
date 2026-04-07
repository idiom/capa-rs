// Instruction text generation wrappers for idalib-rs
// Wraps IDA SDK's ua.hpp print_insn_mnem, generate_disasm_line, print_operand
// and insn_segpref for use via CXX FFI.

#pragma once

#include "pro.h"
#include "ua.hpp"
#include "lines.hpp"

rust::String idalib_print_insn_mnem(uint64_t ea)
{
    auto out = qstring();
    if (print_insn_mnem(&out, ea))
    {
        return rust::String(out.c_str());
    }
    else
    {
        return rust::String();
    }
}

rust::String idalib_generate_disasm_line(uint64_t ea, int32_t flags)
{
    auto out = qstring();
    generate_disasm_line(&out, ea, flags);
    tag_remove(&out);
    return rust::String(out.c_str());
}

rust::String idalib_print_operand(uint64_t ea, int32_t n)
{
    auto out = qstring();
    if (print_operand(&out, ea, n))
    {
        tag_remove(&out);
        return rust::String(out.c_str());
    }
    else
    {
        return rust::String();
    }
}

int32_t idalib_insn_segpref(uint64_t ea)
{
    insn_t insn;
    if (decode_insn(&insn, ea) <= 0)
    {
        return -1;
    }
    return insn.segpref;
}
