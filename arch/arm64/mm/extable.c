// SPDX-License-Identifier: GPL-2.0
/*
 * Based on arch/arm/mm/extable.c
 */

#include <linux/extable.h>
#include <linux/uaccess.h>

bool fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;
	unsigned long addr;

	addr = instruction_pointer(regs);

	/* Search the BPF tables first, these are formatted differently */
	fixup = search_bpf_extables(addr);
	if (fixup)
		return arm64_bpf_fixup_exception(fixup, regs);

	fixup = search_exception_tables(addr);
	if (!fixup)
		return false;

	regs->pc = (unsigned long)&fixup->fixup + fixup->fixup;
	return true;
}
