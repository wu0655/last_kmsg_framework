/*
 *  linux/kernel/printk.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 * Modified to make sys_syslog() more flexible: added commands to
 * return the last 4k of kernel messages, regardless of whether
 * they've been read or not.  Added option to suppress kernel printk's
 * to the console.  Added hook for sending the console messages
 * elsewhere, in preparation for a serial line console (someday).
 * Ted Ts'o, 2/11/93.
 * Modified for sysctl support, 1/8/97, Chris Horn.
 * Fixed SMP synchronization, 08/08/99, Manfred Spraul
 *     manfred@colorfullife.com
 * Rewrote bits to get rid of console_lock
 *	01Mar01 Andrew Morton
 */

#define pr_fmt(fmt) "last: " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h> /* For in_interrupt() */
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/aio.h>
#include <linux/syscalls.h>
#include <linux/kexec.h>
#include <linux/kdb.h>
#include <linux/ratelimit.h>
#include <linux/kmsg_dump.h>
#include <linux/syslog.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/panic_reason.h>
#include <trace/events/printk.h>
#include <linux/utsname.h>
#include <linux/rtc.h>
#include <linux/crc16.h>
#include <linux/panic_reason.h>
#include <linux/unistd.h>
#include <linux/debugfs.h>

#include "printk_i.h"
#include "last_kmsg.h"
#include "last_tz.h"

#ifndef CONFIG_LOG_BUF_MAGIC
	#error "last_kmsg need CONFIG_LOG_BUF_MAGIC"
#endif
static void *p_tz;
extern int power_off_reason;

static struct tzdbg tzdbg = {
	.stat[TZDBG_BOOT].name = "boot",
	.stat[TZDBG_RESET].name = "reset",
	.stat[TZDBG_INTERRUPT].name = "interrupt",
	.stat[TZDBG_VMID].name = "vmid",
	.stat[TZDBG_GENERAL].name = "general",
	.stat[TZDBG_LOG].name = "log",
	.stat[TZDBG_QSEE_LOG].name = "qsee_log",
	.stat[TZDBG_HYP_GENERAL].name = "hyp_general",
	.stat[TZDBG_HYP_LOG].name = "hyp_log",
};

static int _disp_log_stats(struct tzdbg_log_t *log,
			struct tzdbg_log_pos_t *log_start, uint32_t log_len,
			size_t count, uint32_t buf_idx)
{
	uint32_t wrap_start;
	uint32_t wrap_end;
	uint32_t wrap_cnt;
	int max_len;
	int len = 0;
	int i = 0;

	wrap_start = log_start->wrap;
	wrap_end = log->log_pos.wrap;

	/* Calculate difference in # of buffer wrap-arounds */
	if (wrap_end >= wrap_start) {
		wrap_cnt = wrap_end - wrap_start;
	} else {
		/* wrap counter has wrapped around, invalidate start position */
		wrap_cnt = 2;
	}

	if (wrap_cnt > 1) {
		/* end position has wrapped around more than once, */
		/* current start no longer valid                   */
		log_start->wrap = log->log_pos.wrap - 1;
		log_start->offset = (log->log_pos.offset + 1) % log_len;
	} else if ((wrap_cnt == 1) &&
		(log->log_pos.offset > log_start->offset)) {
		/* end position has overwritten start */
		log_start->offset = (log->log_pos.offset + 1) % log_len;
	}

	if (log_start->offset == log->log_pos.offset) {
		memset((void *)tzdbg.disp_buf, 0, LAST_TZ_LOG_LEN);
		memset((void *)log_start, 0, 4);
		return 0;
	}

	max_len = (count > 0x2000) ? 0x2000 : count;

	/*
	 *  Read from ring buff while there is data and space in return buff
	 */
	while ((log_start->offset != log->log_pos.offset) && (len < max_len)) {
		tzdbg.disp_buf[i++] = log->log_buf[log_start->offset];
		log_start->offset = (log_start->offset + 1) % log_len;
		if (0 == log_start->offset)
			++log_start->wrap;
		++len;
	}

	/*
	 * return buffer to caller
	 */
	tzdbg.stat[buf_idx].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_log_stats(size_t count)
{
	static struct tzdbg_log_pos_t log_start = {0};
	struct tzdbg_log_t *log_ptr;

	log_ptr = (struct tzdbg_log_t *)((unsigned char *)p_tz +
				0xB90 -
				offsetof(struct tzdbg_log_t, log_buf));
	pr_info("log_ptr is %lx.\n", (unsigned long int)log_ptr);
	return _disp_log_stats(log_ptr, &log_start,
				0x1470, count, TZDBG_LOG);
}

static ssize_t tzdbgfs_read(struct file *file, char __user *buf,
	size_t count, loff_t *offp)
{
	int len = 0;
	int *tz_id =  file->private_data;

	switch (*tz_id) {
	case TZDBG_LOG:
		pr_info("power_off_reason is %d.\n", power_off_reason);
		/*for long-press-power-key restart, no valid tz log saved, just return.*/
		if ((p_tz == NULL) || (power_off_reason == 1))
			return 0;
		len = _disp_tz_log_stats(count);
		*offp = 0;
		break;
	default:
		break;
	}

	if (len > count)
		len = count;
	pr_info("len is %d.\n", len);
	return simple_read_from_buffer(buf, len, offp,
				tzdbg.stat[(*tz_id)].data, len);
}

static int tzdbgfs_open(struct inode *inode, struct file *pfile)
{
	pfile->private_data = inode->i_private;
	return 0;
}

static long tzdbgfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void *p = NULL;

	switch (cmd) {
	case SET_TZ_LOG_DATA: {
		int order = 0;

		order = get_order(LAST_TZ_LOG_LEN);
		p = (void *)__get_free_pages(GFP_KERNEL, order);
		if (IS_ERR_OR_NULL(p)) {
			WARN(1, "Unable to ioremap reserved memory.\n");
			return 0;
		}

		if (copy_from_user(p, (void *)arg, LAST_TZ_LOG_LEN)) {
			pr_err("%s: Error copying data for last_tz\n", __func__);
			return -EFAULT;
		}

		p_tz = p;
		return 0;
	}
	default:
		pr_err("ioctl is not support\n");
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations tzdbg_fops = {
	.owner   = THIS_MODULE,
	.read    = tzdbgfs_read,
	.open    = tzdbgfs_open,
	.unlocked_ioctl = tzdbgfs_ioctl,
};

int last_tz_dbgfs_init(void)
{
	int rc = 0;
	int i;
	struct dentry           *dent_dir;
	struct dentry           *dent;

	dent_dir = debugfs_create_dir("last_tzdbg", NULL);
	if (dent_dir == NULL) {
		pr_err("last tzdbg debugfs_create_dir failed\n");
		return -ENOMEM;
	}

	for (i = 0; i < TZDBG_STATS_MAX; i++) {
		if (i == TZDBG_LOG) {
			tzdbg.debug_tz[i] = i;
			dent = debugfs_create_file(tzdbg.stat[i].name,
					S_IRUGO, dent_dir,
					&tzdbg.debug_tz[i], &tzdbg_fops);
			if (dent == NULL) {
				pr_err("last TZ debugfs_create_file failed\n");
				rc = -ENOMEM;
				goto err;
			}
		}
	}

	tzdbg.disp_buf = kzalloc(LAST_TZ_LOG_LEN, GFP_KERNEL);
	if (tzdbg.disp_buf == NULL) {
		pr_err("%s: Can't Allocate memory for last_tzdbg.disp_buf\n",
			__func__);

		goto err;
	}

	return 0;
err:
	debugfs_remove_recursive(dent_dir);

	return rc;
}

void last_tz_addr_hook(struct tz_dbg_addr_info *p)
{
	p->last_tz_addr = (u64)TZ_LOG_PHY_ADDR;
	p->last_tz_len = (u32)LAST_TZ_LOG_LEN;
}
