/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TASK_WORK_H
#define _LINUX_TASK_WORK_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

/*
 * Newer kernels use enum task_work_notify_mode and TWA_RESUME here.
 * This Linux 4.19 tree still takes a bool notify argument, where 1 means
 * notify-on-resume. Keep the newer call site source-compatible.
 */
#ifndef TWA_RESUME
#define TWA_RESUME 1
#endif

typedef void (*task_work_func_t)(struct callback_head *);

static inline void
init_task_work(struct callback_head *twork, task_work_func_t func)
{
	twork->func = func;
}

int task_work_add(struct task_struct *task, struct callback_head *twork, bool);
struct callback_head *task_work_cancel(struct task_struct *, task_work_func_t);
void task_work_run(void);

static inline void exit_task_work(struct task_struct *task)
{
	task_work_run();
}

#endif	/* _LINUX_TASK_WORK_H */
