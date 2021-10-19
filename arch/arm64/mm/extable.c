// SPDX-License-Identifier: GPL-2.0
/*
 * Based on arch/arm/mm/extable.c
 */

#include <linux/extable.h>
#include <linux/uaccess.h>

#include <asm/asm-extable.h>

typedef bool (*ex_handler_t)(const struct exception_table_entry *,
			     struct pt_regs *);

static inline unsigned long
get_ex_fixup(const struct exception_table_entry *ex)
{
	return ((unsigned long)&ex->fixup + ex->fixup);
}

static bool ex_handler_fixup(const struct exception_table_entry *ex,
			     struct pt_regs *regs)
{
	regs->pc = get_ex_fixup(ex);
	return true;
}

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

	switch (ex->type) {
	case EX_TYPE_FIXUP:
		return ex_handler_fixup(ex, regs);
	case EX_TYPE_BPF:
		return ex_handler_bpf(ex, regs);
	}

	BUG();
}
