/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SUKISU_4_19_COMPAT_H
#define _LINUX_SUKISU_4_19_COMPAT_H

/*
 * SukiSU-Ultra v4.1.2 calls MODULE_IMPORT_NS(), which was introduced after
 * this Linux 4.19 tree. 4.19 has no symbol namespace import machinery, so the
 * correct compatibility behavior is a no-op.
 *
 * SukiSU v4.1.2 also references __NR_clone3 in its syscall fast path. clone3
 * uses syscall number 435 on arm64, but this 4.19 tree predates the syscall
 * and therefore does not define the macro. Defining only the number keeps the
 * newer source buildable; the old kernel still has no clone3 syscall-table
 * entry, so this case is never observed at runtime.
 *
 * SukiSU's seccomp action-cache helpers are only declared/implemented for
 * kernels >= 5.10.2. Its v4.1.2 setuid hook nevertheless calls the allow-cache
 * helper unconditionally. Linux 4.19 has no seccomp action cache to update, so
 * the correct compatibility behavior is a no-op.
 *
 * Keep this header intentionally dependency-free: it is force-included by
 * KCPPFLAGS during the build, including very early host/kernel objects before
 * generated headers such as generated/timeconst.h exist.
 */
#ifndef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns)
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

#ifndef ksu_seccomp_allow_cache
#define ksu_seccomp_allow_cache(filter, nr) do { } while (0)
#endif

#ifndef ksu_seccomp_clear_cache
#define ksu_seccomp_clear_cache(filter, nr) do { } while (0)
#endif

#endif /* _LINUX_SUKISU_4_19_COMPAT_H */
