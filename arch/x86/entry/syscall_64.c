// SPDX-License-Identifier: GPL-2.0-only
/* 64-bit system call dispatch */

#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <linux/syscalls.h>
#include <linux/entry-common.h>
#include <linux/nospec.h>
#include <asm/syscall.h>

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#define __SYSCALL_NORETURN(nr, sym) extern long __noreturn __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#ifdef CONFIG_X86_X32_ABI
#include <asm/syscalls_x32.h>
#endif
#undef  __SYSCALL

#undef  __SYSCALL_NORETURN
#define __SYSCALL_NORETURN __SYSCALL

#ifdef CONFIG_SAFEFETCH
#include <linux/safefetch.h>
#include <linux/region_allocator.h>
#include <linux/mem_range.h>
#include <linux/safefetch_static_keys.h>
#ifdef SAFEFETCH_WHITELISTING
#warning "Using DFCACHER whitelisting"
static noinline void should_whitelist(unsigned long syscall_nr)
{
	switch (syscall_nr) {
	case __NR_futex:
	case __NR_execve:
	case __NR_writev:
	case __NR_pwritev2:
	case __NR_pwrite64:
	case __NR_write:
			current->df_prot_struct_head.is_whitelisted = 1;
			return;
	}
	current->df_prot_struct_head.is_whitelisted = 0;
}
#endif
#endif

/*
 * The sys_call_table[] is no longer used for system calls, but
 * kernel/trace/trace_syscalls.c still wants to know the system
 * call address.
 */
#define __SYSCALL(nr, sym) __x64_##sym,
const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};
#undef  __SYSCALL

#define __SYSCALL(nr, sym) case nr: return __x64_##sym(regs);
long x64_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_64.h>
	default: return __x64_sys_ni_syscall(regs);
	}
}

#ifdef CONFIG_X86_X32_ABI
long x32_sys_call(const struct pt_regs *regs, unsigned int nr)
{
	switch (nr) {
	#include <asm/syscalls_x32.h>
	default: return __x64_sys_ni_syscall(regs);
	}
}
#endif

static __always_inline bool do_syscall_x64(struct pt_regs *regs, int nr)
{
	/*
	 * Convert negative numbers to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int unr = nr;

	if (likely(unr < NR_syscalls)) {
		unr = array_index_nospec(unr, NR_syscalls);
		regs->ax = x64_sys_call(regs, unr);
		return true;
	}
	return false;
}

static __always_inline bool do_syscall_x32(struct pt_regs *regs, int nr)
{
	/*
	 * Adjust the starting offset of the table, and convert numbers
	 * < __X32_SYSCALL_BIT to very high and thus out of range
	 * numbers for comparisons.
	 */
	unsigned int xnr = nr - __X32_SYSCALL_BIT;

	if (IS_ENABLED(CONFIG_X86_X32_ABI) && likely(xnr < X32_NR_syscalls)) {
		xnr = array_index_nospec(xnr, X32_NR_syscalls);
		regs->ax = x32_sys_call(regs, xnr);
		return true;
	}
	return false;
}

/* Returns true to return using SYSRET, or false to use IRET */
__visible noinstr bool do_syscall_64(struct pt_regs *regs, int nr)
{
	add_random_kstack_offset();
	// If interrupts using current execute prior to the next syscall
	// then we will enter the syscall with the mem_range initialized
	// we could chose to clean this info (shrink_region) or simply
	// trust that the interrupt doesn't fetch something nasty and just
	// operate the next syscall on the interrupt state (happens for
	// sigaction calls mostly during IPI's that save the signal frame
	// prior to executing a sigaction call). Or simply clear state
	// on irq end (might slow down irqs so avoid this).
#if defined(CONFIG_SAFEFETCH)
	IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key) {
		if (unlikely(SAFEFETCH_MEM_RANGE_INIT_FLAG)) {
			// An IPI probably sent us a signal and the signal
			// enabled the defense in interrupt context. Reset
			// dfcache interrupt state.
#ifndef SAFEFETCH_DEBUG
			// If in debug mode, we actually reset the range in
			// df_debug_syscall_entry.
			SAFEFETCH_RESET_MEM_RANGE();
#endif
			shrink_region(DF_CUR_STORAGE_REGION_ALLOCATOR);
			shrink_region(DF_CUR_METADATA_REGION_ALLOCATOR);
		}
	}
#endif

#ifdef SAFEFETCH_MEASURE_DEFENSE
	// We only use this for measuring so execute this without the static key
	// else we get into nasty scenarios if we miss this initialization step.
	df_init_measure_structs(current);
#endif
	nr = syscall_enter_from_user_mode(regs, nr);
#if defined(CONFIG_SAFEFETCH) && defined(SAFEFETCH_WHITELISTING)
	should_whitelist(nr);
#endif

#if defined(CONFIG_SAFEFETCH) && defined(SAFEFETCH_DEBUG)
	IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key) {
		df_debug_syscall_entry(nr, regs);
	}
#endif
	instrumentation_begin();

	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
		/* Invalid system call, but still a system call. */
		regs->ax = __x64_sys_ni_syscall(regs);
	}

	instrumentation_end();
	syscall_exit_to_user_mode(regs);

#ifdef CONFIG_SAFEFETCH
	// Note, we might have rseq regions executing in syscall_exit_to_user_mode
	// and irqs so delay resetting region after this.
	IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_hooks_key) {
#ifdef SAFEFETCH_DEBUG
		df_debug_syscall_exit();
#endif
#ifdef SAFEFETCH_MEASURE_DEFENSE
		df_destroy_measure_structs();
#endif
		reset_regions();
	}
#endif

	/*
	 * Check that the register state is valid for using SYSRET to exit
	 * to userspace.  Otherwise use the slower but fully capable IRET
	 * exit path.
	 */

	/* XEN PV guests always use the IRET path */
	if (cpu_feature_enabled(X86_FEATURE_XENPV))
		return false;

	/* SYSRET requires RCX == RIP and R11 == EFLAGS */
	if (unlikely(regs->cx != regs->ip || regs->r11 != regs->flags))
		return false;

	/* CS and SS must match the values set in MSR_STAR */
	if (unlikely(regs->cs != __USER_CS || regs->ss != __USER_DS))
		return false;

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * TASK_SIZE_MAX covers all user-accessible addresses other than
	 * the deprecated vsyscall page.
	 */
	if (unlikely(regs->ip >= TASK_SIZE_MAX))
		return false;

	/*
	 * SYSRET cannot restore RF.  It can restore TF, but unlike IRET,
	 * restoring TF results in a trap from userspace immediately after
	 * SYSRET.
	 */
	if (unlikely(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)))
		return false;

	/* Use SYSRET to exit to userspace */
	return true;
}
