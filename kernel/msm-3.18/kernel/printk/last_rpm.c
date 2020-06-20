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
#include "last_rpm.h"

#ifndef CONFIG_LOG_BUF_MAGIC
	#error "last_kmsg need CONFIG_LOG_BUF_MAGIC"
#endif

static void *p_rpm;
static struct RPM_ULOG_STRUCT *p_rpm_cfg;

#define APPS_NON_SECURE_WD_BITE 0xEA
#define APPS_TZ_HALT 0xE9
#define RPM_ERROR_FATAL 0xD3

static ssize_t rpm_dbgfs_read(struct file *file, char __user *buf,
	size_t count, loff_t *offp)
{
	uint32_t index;
	char *buffer;
	struct rpm_ext_log *rpm_log;

	char *app_non_secure_wd_bite = (char *)"rpm_abort_interrupt_received (APPS NON SECURE WD BITE) ... aborting.\n";
	char *app_tz_halt = (char *)"rpm_abort_interrupt_received (TZ HALT) ... aborting.\n";
	char *rpm_err_fatal = (char *)"rpm_err_fatal.\n";
	size_t len;

	pr_err("%s: enter.\n", __func__);
	p_rpm_cfg->buffer = p_rpm;
	buffer = p_rpm_cfg->buffer;

	for(index = 0; index < 0x2000; index+=sizeof(struct rpm_ext_log)){
		rpm_log = (struct rpm_ext_log *)(&buffer[index]);
		if(rpm_log->id == APPS_NON_SECURE_WD_BITE){
			pr_err("%s: find id %d at index %d.\n", __func__,rpm_log->id ,index);
			len =  strlen(app_non_secure_wd_bite);
			return simple_read_from_buffer(buf, len, offp,	app_non_secure_wd_bite, len);
		}
		else if(rpm_log->id == APPS_TZ_HALT){
			pr_err("%s: find id %d at index %d.\n", __func__,rpm_log->id ,index);
			len =  strlen(app_tz_halt);
			return simple_read_from_buffer(buf, len, offp,	app_tz_halt, len);
		}
		else if(rpm_log->id == RPM_ERROR_FATAL){
			pr_err("%s: find id %d at index %d.\n", __func__,rpm_log->id ,index);
			len =  strlen(rpm_err_fatal);
			return simple_read_from_buffer(buf, len, offp,	rpm_err_fatal, len);
		}
	}
	return 0;
}

static int rpm_dbgfs_open(struct inode *inode, struct file *pfile)
{
	pfile->private_data = inode->i_private;
	return 0;
}

static long rpm_dbgfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void *p = NULL;

	switch (cmd) {
	case SET_RPM_CFG_DATA: {
		int order = 0;

		order = get_order(LAST_RPM_CFG_LEN);
		p = (void *)__get_free_pages(GFP_KERNEL, order);
		if (IS_ERR_OR_NULL(p)) {
			WARN(1, "Unable to ioremap reserved memory.\n");
			return 0;
		}

		if (copy_from_user(p, (void *)arg, LAST_RPM_CFG_LEN)) {
			pr_err("%s: Error copying data for last_rpm_cfg\n", __func__);
			return -EFAULT;
		}

		p_rpm_cfg = p;
		return 0;
	}
	case SET_RPM_LOG_DATA: {
		int order = 0;

		order = get_order(LAST_RPM_LOG_LEN);
		p = (void *)__get_free_pages(GFP_KERNEL, order);
		if (IS_ERR_OR_NULL(p)) {
			WARN(1, "Unable to ioremap reserved memory.\n");
			return 0;
		}

		if (copy_from_user(p, (void *)arg, LAST_RPM_LOG_LEN)) {
			pr_err("%s: Error copying data for last_kmsg\n", __func__);
			return -EFAULT;
		}

		p_rpm = p;
		return 0;
	}

	default:
		pr_err("ioctl cmd %d is not support\n",cmd);
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations rpm_dbg_fops = {
	.owner   = THIS_MODULE,
	.read    = rpm_dbgfs_read,
	.open    = rpm_dbgfs_open,
	.unlocked_ioctl = rpm_dbgfs_ioctl,
};

int last_rpm_dbgfs_init(void)
{
	int rc = 0;
	struct dentry *dent_dir;
	struct dentry *dent;

	dent_dir = debugfs_create_dir("last_rpmdbg", NULL);
	if (dent_dir == NULL) {
		pr_err("last rpmdbg debugfs_create_dir failed\n");
		return -ENOMEM;
	}

	dent = debugfs_create_file("log",
				S_IRUGO, dent_dir,
				NULL, &rpm_dbg_fops);
	if (dent == NULL) {
		pr_err("last RPM debugfs_create_file failed\n");
		rc = -ENOMEM;
		goto err;
	}
	return 0;
err:
	debugfs_remove_recursive(dent_dir);

	return rc;
}

void last_rpm_addr_hook(struct rpm_dbg_addr_info *p)
{
	p->last_rpm_addr = (u64)RPM_LOG_PHY_ADDR;
	p->last_rpm_len = (u32)LAST_RPM_LOG_LEN;
	p->last_rpm_cfg_addr= (u64)RPM_CFG_PHY_ADDR;
	p->last_rpm_cfg_len = (u32)LAST_RPM_CFG_LEN;
}
