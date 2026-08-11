/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SUKISU_4_19_COMPAT_H
#define _LINUX_SUKISU_4_19_COMPAT_H

/*
 * SukiSU-Ultra v4.1.2 calls MODULE_IMPORT_NS(), which was introduced after
 * this Linux 4.19 tree. 4.19 has no symbol namespace import machinery, so the
 * correct compatibility behavior is a no-op.
 *
 * Keep this header intentionally dependency-free: it is force-included by
 * KCPPFLAGS during the build, including very early host/kernel objects before
 * generated headers such as generated/timeconst.h exist.
 */
#ifndef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns)
#endif

#endif /* _LINUX_SUKISU_4_19_COMPAT_H */
