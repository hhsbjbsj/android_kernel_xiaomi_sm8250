/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MOUNT_H
#define _UAPI_LINUX_MOUNT_H

/*
 * Linux 4.19 compatibility shim for SukiSU-Ultra v4.1.2.
 *
 * v4.1.2 includes <uapi/linux/mount.h>, a header introduced after this
 * kernel baseline. su_mount_ns.c only uses legacy mount flags (MS_PRIVATE,
 * MS_REC), which are already provided by this tree through <linux/fs.h>.
 * Keep this shim intentionally empty instead of importing newer mount API
 * definitions that the 4.19 VFS does not implement.
 */

#endif /* _UAPI_LINUX_MOUNT_H */
