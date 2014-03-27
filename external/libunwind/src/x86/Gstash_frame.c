/* libunwind - a platform-independent unwind library
   Copyright (C) 2011 by FERMI NATIONAL ACCELERATOR LABORATORY
     Adjusted for x86 from x86_64 by Paul Pluzhnikov <address@hidden>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include "unwind_i.h"

HIDDEN void
tdep_stash_frame (struct dwarf_cursor *d, struct dwarf_reg_state *rs)
{
  struct cursor *c = (struct cursor *) dwarf_to_cursor (d);
  unw_tdep_frame_t *f = &c->frame_info;

  Debug (4, "ip=0x%lx cfa=0x%lx type %d cfa [where=%d val=%ld] cfaoff=%ld"
	 " ra=0x%lx ebp [where=%d val=%ld @0x%lx] esp [where=%d val=%ld @0x%lx]\n",
	 d->ip, d->cfa, f->frame_type,
	 rs->reg[DWARF_CFA_REG_COLUMN].where,
	 rs->reg[DWARF_CFA_REG_COLUMN].val,
	 rs->reg[DWARF_CFA_OFF_COLUMN].val,
	 DWARF_GET_LOC(d->loc[d->ret_addr_column]),
	 rs->reg[EBP].where, rs->reg[EBP].val, DWARF_GET_LOC(d->loc[EBP]),
	 rs->reg[ESP].where, rs->reg[ESP].val, DWARF_GET_LOC(d->loc[ESP]));

  /* A standard frame is defined as:
      - CFA is register-relative offset off EBP or ESP;
      - Return address is saved at CFA-8;
      - EBP is unsaved or saved at CFA+offset, offset != -1;
      - ESP is unsaved or saved at CFA+offset, offset != -1.  */
  if (f->frame_type == UNW_X86_FRAME_OTHER
      && (rs->reg[DWARF_CFA_REG_COLUMN].where == DWARF_WHERE_REG)
      && (rs->reg[DWARF_CFA_REG_COLUMN].val == EBP
	  || rs->reg[DWARF_CFA_REG_COLUMN].val == ESP)
      && labs(rs->reg[DWARF_CFA_OFF_COLUMN].val) < (1 << 29)
      && DWARF_GET_LOC(d->loc[d->ret_addr_column]) == d->cfa-8
      && (rs->reg[EBP].where == DWARF_WHERE_UNDEF
	  || rs->reg[EBP].where == DWARF_WHERE_SAME
	  || (rs->reg[EBP].where == DWARF_WHERE_CFAREL
	      && labs(rs->reg[EBP].val) < (1 << 14)
	      && rs->reg[EBP].val+1 != 0))
      && (rs->reg[ESP].where == DWARF_WHERE_UNDEF
	  || rs->reg[ESP].where == DWARF_WHERE_SAME
	  || (rs->reg[ESP].where == DWARF_WHERE_CFAREL
	      && labs(rs->reg[ESP].val) < (1 << 14)
	      && rs->reg[ESP].val+1 != 0)))
  {
    /* Save information for a standard frame. */
    f->frame_type = UNW_X86_FRAME_STANDARD;
    f->cfa_reg_esp = (rs->reg[DWARF_CFA_REG_COLUMN].val == ESP);
    f->cfa_reg_offset = rs->reg[DWARF_CFA_OFF_COLUMN].val;
    if (rs->reg[EBP].where == DWARF_WHERE_CFAREL)
      f->ebp_cfa_offset = rs->reg[EBP].val;
    if (rs->reg[ESP].where == DWARF_WHERE_CFAREL)
      f->esp_cfa_offset = rs->reg[ESP].val;
    Debug (4, " standard frame\n");
  }

  /* Signal frame was detected via augmentation in tdep_fetch_frame()
     and partially filled in tdep_reuse_frame().  Now that we have
     the delta between inner and outer CFAs available to use, fill in
     the offsets for CFA and stored registers.  We don't have space
     for RIP, it's location is calculated relative to EBP location. */
  else if (f->frame_type == UNW_X86_FRAME_SIGRETURN)
  {
    assert (f->cfa_reg_offset == -1);
    f->cfa_reg_offset = d->cfa - c->sigcontext_addr;
    f->ebp_cfa_offset = DWARF_GET_LOC(d->loc[EBP]) - d->cfa;
    f->esp_cfa_offset = DWARF_GET_LOC(d->loc[ESP]) - d->cfa;
    Debug (4, " sigreturn frame ebpoff %d espoff %d\n",
	   f->ebp_cfa_offset, f->esp_cfa_offset);
  }

  /* PLT and guessed EBP-walked frames are handled in unw_step(). */
  else
    Debug (4, " unusual frame\n");
}
