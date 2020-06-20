/* Copyright (c) 2012-2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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
#include <linux/qpnp/qpnp-power-on.h>

#include "printk_i.h"
#include "last_kmsg.h"

#ifndef CONFIG_LOG_BUF_MAGIC
	#error "last_kmsg need CONFIG_LOG_BUF_MAGIC"
#endif

int last_kmsg_init_status = LASK_KMSG_UNINIT;
int dump_proc_file_node_flg;
int dump_crc_result;

/*======================================
* debug  for last_kmsg
*=======================================
*/
static int last_debug_mask;
module_param_named(
	debug_mask, last_debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP
);

/*
* ********************NOTICE***********************
*
* Most of function of this file is a clone of the functions in
* printk.c.
* If the function in printk.c change, this file must be changed
* accordingly.
*
*/
static char *log_buf_la;
static u32 log_buf_len_la;
struct last_kmsg_info *last_info_ptr;
struct pon_poff_info *pon_poff_info_ptr;

/*======================================
* definetion for last_kmsg
*=======================================
*/
#define FIRST_RUN_DELAY_IN_MS (8*1000)
#define TRY_DELAY_IN_MS (2*1000)
#define TRY_MAX_TIMES (30)
#define LAST_KMSG_LOG_BROKEN		(0x9999)
#define MAX_READ_LEN ((__LOG_BUF_LEN) + ((__LOG_BUF_LEN) >> 2))

static int last_kmsg_open
	(struct inode *inode, struct file *file);
static int last_kmsg_release
	(struct inode *inode, struct file *file);
static ssize_t last_kmsg_bin_read
	(struct file *, char __user *, size_t , loff_t *);
static ssize_t last_kmsg_print_all
	(struct file *, char __user *, size_t, loff_t *);
static long last_kmsg_ioctl
	(struct file *, unsigned int, unsigned long);
static ssize_t last_kmsg_set
	(struct file *, const char __user *, size_t, loff_t *);

struct last_kmsg_user {
	u64 seq;
	u32 idx;
	u64 next_seq;
	u32 next_idx;
	int last_kmsg_avail;
	int pon_poff_reason;
};

static int flg;

static const struct file_operations last_kmsg_file_ops = {
	.owner = THIS_MODULE,
	.open = last_kmsg_open,
	.read = last_kmsg_print_all,
	.write = last_kmsg_set,
	.unlocked_ioctl = last_kmsg_ioctl,
	.release = last_kmsg_release,
};

static const struct file_operations last_kmsg_bin_file_ops = {
	.owner = THIS_MODULE,
	.read = last_kmsg_bin_read,
};

/*
* ********************NOTICE***********************
*
* log_next()
* log_from_idx()

* The 2 functions are redefine here, because the functions
* in printk.c access to const array log_buf[]
* although we also could use the log_buf as name for
* last_kmsg buffer, but it could make ram_parser not work.
* ram_parser is a tool from Qualcomm to parse ramdump to
* get kmsg in dump.
*/
static struct printk_log *log_from_idx(u32 idx, char *buf)
{
	struct printk_log *msg;

	msg = (struct printk_log *)(buf + idx);

	if (!msg->len)
		return (struct printk_log *)buf;
	return msg;
}

static u32 log_next(u32 idx, char *buf)
{
	struct printk_log *msg;

	msg = (struct printk_log *)(buf + idx);

	if (!msg->len) {
		msg = (struct printk_log *)buf;
		return msg->len;
	}
	return idx + msg->len;
}

static ssize_t last_kmsg_pkg_scan(void)
{
	char *last_kmsg_buf = log_buf_la;
	u64 next_seq = last_info_ptr->log_next_seq;
	u64 seq = last_info_ptr->log_first_seq;
	u32 idx = last_info_ptr->log_first_idx;

	enum log_flags prev = 0;
	int len = 0;

	while (len >= 0 && seq < next_seq) {
		struct printk_log *msg;
		int textlen;

		if (idx > (__LOG_BUF_LEN - sizeof(struct printk_log))) {
			pr_err("Error: idx error idx=%u.\n", idx);
			len = -LAST_KMSG_LOG_BROKEN;
			break;
		}

		msg = log_from_idx(idx, last_kmsg_buf);
		if (msg->magic != LOG_MAGIC_VAL) {
			pr_err("Error: magic error idx=%u magic=0x%x.\n",
					idx, msg->magic);
			len = -LAST_KMSG_LOG_BROKEN;
			break;
		}

		textlen = msg_print_text(msg, prev, true, NULL, 0);

		if (textlen < 0) {
			pr_err("Error: textlen error idx=%u textlen=%d.\n",
					idx, textlen);
			len = -LAST_KMSG_LOG_BROKEN;
			break;
		}

		idx = log_next(idx, last_kmsg_buf);
		seq++;
		prev = msg->flags;

		len += textlen;
	}

	return len;
}

static int last_kmsg_print
	(struct file *file, void __user *buf, loff_t pos, size_t count)
{
	struct last_kmsg_user *user = file->private_data;
	char *text = NULL;
	char *last_kmsg_buf = NULL;
	int len = 0;
	u64 next_seq;
	u64 seq;
	u32 idx;
	enum log_flags prev;

	if (buf == NULL)
		return 0;

	text = kmalloc(LOG_LINE_MAX + PREFIX_MAX, GFP_KERNEL);
	if (!text)
		return -ENOMEM;

	last_kmsg_buf = log_buf_la;
	/* last message fitting into this dump */
	next_seq = last_info_ptr->log_next_seq;
	len = 0;
	prev = 0;
	idx = user->idx;
	seq = user->seq;

	while (len >= 0 && seq < next_seq) {
		struct printk_log *msg;
		int textlen;

		if (idx > (__LOG_BUF_LEN - sizeof(struct printk_log))) {
			pr_err("Error: idx error idx=%u.\n", idx);
			break;
		}

		if (last_debug_mask & 0x02)
			pr_info("idx= %u seq= %llu\n", idx, seq);

		msg = log_from_idx(idx, last_kmsg_buf);
		textlen = msg_print_text(msg, prev, true,
					text, LOG_LINE_MAX + PREFIX_MAX);

		if (textlen < 0) {
			/* error report*/
			pr_err("Error: textlen error idx=%u textlen=%d.\n",
					idx, textlen);
			len = textlen;
			break;
		}

		if ((len + textlen) > count) {
			/* buf is nearly full.*/
			break;
		}

		idx = log_next(idx, last_kmsg_buf);
		seq++;
		prev = msg->flags;

		if (copy_to_user(buf + len, text, textlen)) {
			pr_err("copy_to_user fail in %s.\n", __func__);
			len = -EFAULT;
			break;
		}

		len += textlen;
	}

	user->idx = idx;
	user->seq = seq;

	kfree(text);
	return len;
}

static char *g_pon_poff_str;
int power_off_reason = 0;
char *get_pon_poff_string(void)
{
	struct pon_poff_info *p = pon_poff_info_ptr;
	uint32 val = 0;
	char *buff = NULL;
	size_t buff_len = PAGE_SIZE;
	int len, ret;

	if (g_pon_poff_str != NULL)
		return g_pon_poff_str;

	buff = kmalloc(buff_len, GFP_KERNEL);
	if (!buff)
		return NULL;
	len = 0;

	/* head  */
	ret = snprintf(buff + len, buff_len - len,
			"\n\nLAST INFO IS SAVED AFTER REBOOT. BOOT INFO OF __THE__ REBOOT:\n");
	len += ret;

	/* raw value */
	ret = snprintf(buff + len, buff_len - len,
			"PON SUMMARY: PM0=%llx PM1=%llx gcc_reset_status=0x%x\n",
			p->pm0, p->pm1, p->reset_status_reg);
	len += ret;

	/* power on status */
	ret = snprintf(buff + len, buff_len - len,
			"Power ON REASON: %s\n", pon_to_str(p->pm0 & 0xff));
	len += ret;

	/* warm reset on status */
	val = (p->pm0 & 0xffff0000) >> 16;
	if (val) {
		ret = snprintf(buff + len, buff_len - len,
			"WARM RESET: %s\n", wam_reset_to_str(val));
		len += ret;
	}

	/* power off status */
	val = (p->pm0 & 0xffff00000000) >> 32;
	power_off_reason = (val & 0x80) != 0 ? 1:0;
	if (val) {
		ret = snprintf(buff + len, buff_len - len,
			"Power OFF REASON: %s\n", poff_to_str(val));
		len += ret;
	}

	g_pon_poff_str = buff;
	return buff;
}

int put_pon_poff_string(void)
{
	if (g_pon_poff_str != NULL) {
		kfree(g_pon_poff_str);
		g_pon_poff_str = NULL;
	}

	return 0;
}

static ssize_t last_kmsg_print_pon_poff
	(struct file *file, char __user *buf, size_t len,  loff_t *offset)
{

	char *p = NULL;
	int plen, ret;

	p = get_pon_poff_string();
	if (p == NULL)
		return 0;
	plen = strlen(p);

	ret = simple_read_from_buffer(buf, len, offset, p, plen);

	if (ret == 0)
		put_pon_poff_string();

	return ret;
}

static ssize_t last_kmsg_print_all
	(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
	struct last_kmsg_user *user = file->private_data;

	loff_t pos = *offset;
	int ret = 0;

	/* the data in kmsg buffer is stored in packet. when it expand to string
	* sometimes, it'll greater than buffer size. so set MAX_READ_LEN larger
	* than __LOG_BUF_LEN
	*/
	if ((pos < 0) || (pos > MAX_READ_LEN))
		return -EINVAL;

	/* print last_kmsg. if not avail, print last_kmsg_init_status */
	if (user->last_kmsg_avail == 2) {
		ret = last_kmsg_print(file, buf, pos, len);
		if (ret > 0) {
			*offset = pos + ret;
			goto exit;
		}
		user->last_kmsg_avail = 0;
	} else if (user->last_kmsg_avail == 1) {
		char temp_buf[64];
		int len = snprintf(temp_buf, 64,
				"last_kmsg_init_status = %d\n",
				last_kmsg_init_status);

		if (copy_to_user(buf, temp_buf, len)) {
			pr_info("copy data error.\n");
			return -EFAULT;
		}
		ret = len;
		user->last_kmsg_avail = 0;
	}
	if (ret > 0)
		goto exit;

	/* print pon and poff  when last_kmsg is saved. */
	if (user->pon_poff_reason == 2) {
		user->pon_poff_reason = 1;
		*offset = 0;
	}
	if (user->pon_poff_reason == 1) {
		ret = last_kmsg_print_pon_poff(file, buf, len, offset);
		if (ret == 0)
			user->pon_poff_reason = 0;
	}

exit:
	return ret;
}

static ssize_t last_kmsg_set
	(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (count) {
		char c;

		if (get_user(c, buf))
			return -EFAULT;
		if (c != '0')
			flg = c - '0';
	}
	return count;
}

static void last_kmsg_set_first(struct last_kmsg_user *user)
{
	if (last_kmsg_init_status == LAST_KMSG_GOOD)
		user->last_kmsg_avail = 2;
	else
		user->last_kmsg_avail = 1;

	user->idx = last_info_ptr->log_first_idx;
	user->seq = last_info_ptr->log_first_seq;
	user->next_idx = last_info_ptr->log_next_idx;
	user->next_seq = last_info_ptr->log_next_seq;
	user->pon_poff_reason = 2;
}

static int last_kmsg_open(struct inode *inode, struct file *file)
{
	struct last_kmsg_user *user;
	/* write-only does not need any file context */
	if ((file->f_flags & O_ACCMODE) == O_WRONLY)
		return 0;

#ifdef FEATURE_NOT_AVAILABLE_BY_LETV
	{
	int err;

	err = check_syslog_permissions(SYSLOG_ACTION_READ_ALL,
				       SYSLOG_FROM_READER);
	if (err)
		return err;
	}
#endif

	user = kmalloc(sizeof(struct last_kmsg_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	if (last_kmsg_init_status != LASK_KMSG_UNINIT)
		last_kmsg_set_first(user);
	file->private_data = user;

	pr_info("%s\n", __func__);
	return 0;
}

/* return 1 if match, 0 for mismatch */
static inline int check_crc16(void *buf, size_t size, u16 crc)
{
	u16 crc_new = crc16(CRC16_START_VAL, buf, size);

	if (crc_new != crc)
		pr_info("crc =0x%hx crc_new=0x%hx", crc, crc_new);
	return (crc_new == crc);
}

/*
* For the 4 critical global variable, each one has a crc16 value.
* if crc16 match, means the variable is right.
* return value:
*	-1 ----last_kmsg is no valid
*	0  ---- partly broken
*	1  ----valid
*/
static int check_last_kmsg_crc16(struct last_kmsg_info *p)
{
	int crc_valid_cnt = 0;
	int ret = 0;

	/* if all idx and seq are 0, last_kmsg is invalid. */
	if ((p->log_first_idx == 0)
		&& (p->log_first_seq == 0)
		&& (p->log_next_idx == 0)
		&& (p->log_next_seq == 0)) {
		pr_warn("info of last_kmsg lost\n");
		ret = -1;
		goto exit;
	}

	/*log_first_idx*/
	ret = check_crc16((void *)(&p->log_first_idx),
					sizeof(p->log_first_idx),
					p->log_first_idx_crc16);
	if (ret)
		crc_valid_cnt |= 0x1;

	/*log_first_seq*/
	ret = check_crc16((void *)(&p->log_first_seq),
					sizeof(p->log_first_seq),
					p->log_first_seq_crc16);
	if (ret)
		crc_valid_cnt |= 0x2;


	/*log_next_idx*/
	ret = check_crc16((void *)(&p->log_next_idx),
					sizeof(p->log_next_idx),
					p->log_next_idx_crc16);
	if (ret)
		crc_valid_cnt |= 0x4;


	/*log_next_seq*/
	ret = check_crc16((void *)(&p->log_next_seq),
					sizeof(p->log_next_seq),
					p->log_next_seq_crc16);
	if (ret)
		crc_valid_cnt |= 0x8;

	pr_info("crc16 check, right cnt=0x%x\n", crc_valid_cnt);
	if (crc_valid_cnt == 0)
		ret = -1;
	else if (crc_valid_cnt == 0xf)
		ret = 1;
	else
		ret = 0;

exit:
	return ret;
}

void dump_last_kmsg_info(void)
{
	pr_info("\n---dump last_kmsg_info begin---\n");
	pr_info("---last_kmsg_init_status=%d\n", last_kmsg_init_status);
	pr_info("---dump last_panic_info end---\n");
}

int last_kmsg_post_init(void)
{
	int ret;

	ret = check_last_kmsg_crc16(last_info_ptr);
	if (ret <  0)
		last_kmsg_init_status = LAST_KMSG_CRC_ALL_ERROR;
	else if (ret == 0)
		last_kmsg_init_status = LAST_KMSG_CRC_ERROR;
	else {
		ret = last_kmsg_pkg_scan();
		if (ret < 0)
			last_kmsg_init_status = LAST_KMSG_SCAN_FAIL;
		else
			last_kmsg_init_status = LAST_KMSG_GOOD;
	}

	if (last_kmsg_init_status != LAST_KMSG_GOOD)
		proc_create("last_kmsg_bin", S_IRUGO, NULL,
				&last_kmsg_bin_file_ops);

	return 0;
}

static long last_kmsg_ioctl
	(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void *p = NULL;
	int ret;

	switch (cmd) {
	case SET_LK_LOG_DATA: {
		int order = 0;

		order = get_order(__LOG_BUF_LEN);
		p = (void *)__get_free_pages(GFP_KERNEL, order);
		if (IS_ERR_OR_NULL(p)) {
			WARN(1, "Unable to ioremap reserved memory.\n");
			return 0;
		}

		ret = copy_from_user(p, (void *)arg, __LOG_BUF_LEN);
		if (ret) {
			pr_err("%s: Error copying data\n", __func__);
			return -EFAULT;
		}

		log_buf_la = p;
		log_buf_len_la = __LOG_BUF_LEN;
		return 0;
	}

	case SET_LK_LOG_INFO: {
		int len = sizeof(struct last_kmsg_info);

		p = kmalloc(len, GFP_KERNEL);
		if (p == NULL)
			return -ENOMEM;

		ret = copy_from_user(p, (void *)arg, len);
		if (ret) {
			pr_err("%s: Error copying for last info\n", __func__);
			kfree(p);
			return -EFAULT;
		}

		last_info_ptr = p;
		return 0;
	}

	case SET_LK_PON_POFF_INFO: {
		int len = sizeof(struct pon_poff_info);

		p = kmalloc(len, GFP_KERNEL);
		if (p == NULL)
			return -ENOMEM;

		ret = copy_from_user(p, (void *)arg, len);
		if (ret) {
			pr_err("%s: Error copying for last info\n", __func__);
			kfree(p);
			return -EFAULT;
		}

		pon_poff_info_ptr = p;
		return 0;
	}

	case LK_POST_INIT: {
		struct last_kmsg_user *user = filp->private_data;
		/* sanity check */
		if (!(log_buf_la && pon_poff_info_ptr && last_info_ptr)) {
			pr_err("%s: Error ioctl sequence error\n", __func__);
			return -EFAULT;
		}
		ret = last_kmsg_post_init();
		last_kmsg_set_first(user);

		return ret;
	}

	default:
		pr_err("ioctl is not support\n");
		return -EINVAL;
	}

	return 0;
}

static int last_kmsg_release(struct inode *inode, struct file *file)
{
	struct last_kmsg_user *user = file->private_data;

	if (user != NULL)
		kfree(user);

	pr_info("%s\n", __func__);
	return 0;
}

int last_kmsg_init(void)
{
	proc_create("last_kmsg", S_IRUGO|S_IWUGO, NULL, &last_kmsg_file_ops);
	return 0;
}

#ifdef NOT_USED_CODE
char *g_last_kmsg_index_ptr = NULL;
static char *get_last_kmsg_desc(void)
{
	static char *p;
	int len = PAGE_SIZE;
	int total, ret;

	if (g_last_kmsg_index_ptr != NULL)
		return g_last_kmsg_index_ptr;

	p = kmalloc(len, GFP_KERNEL);
	if (p == NULL)
		return NULL;

	total = 0;
	ret = snprintf(p, len, "\n\n\nidx=%u\n",
			last_info_ptr->log_first_idx);
	total = ret;
	ret = snprintf(p+total, len-total, "seq=%llu\n",
			last_info_ptr->log_first_seq);
	total += ret;
	ret = snprintf(p+total, len-total, "next_idx=%u\n",
			last_info_ptr->log_next_idx);
	total += ret;
	ret = snprintf(p+total, len-total, "next_seq=%llu\n",
			last_info_ptr->log_next_seq);
	total += ret;
	ret = snprintf(p, len, "log_first_seq_crc16=%u\n",
			last_info_ptr->log_first_seq_crc16);
	total = ret;
	ret = snprintf(p+total, len-total, "log_first_idx_crc16=%u\n",
			last_info_ptr->log_first_idx_crc16);
	total += ret;
	ret = snprintf(p+total, len-total, "log_next_seq_crc16=%u\n",
			last_info_ptr->log_next_seq_crc16);
	total += ret;
	ret = snprintf(p+total, len-total, "log_next_idx_crc16=%u\n",
			last_info_ptr->log_next_idx_crc16);
	total += ret;

	g_last_kmsg_index_ptr = p;
	return p;
}

static int put_last_kmsg_desc(void)
{
	if (g_last_kmsg_index_ptr != NULL) {
		kfree(g_last_kmsg_index_ptr);
		g_last_kmsg_index_ptr = NULL;
	}

	return 0;
}
#endif

static ssize_t last_kmsg_bin_read
	(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
	int ret;
	char *p = log_buf_la;
	int plen = __LOG_BUF_LEN;

	ret = simple_read_from_buffer(buf, len, offset, p, plen);

	return ret;
}
