/*
 *  linux/kernel/printk.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 * LETV---wupeng
 */
#define pr_fmt(fmt) "last: " fmt

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/ratelimit.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <trace/events/printk.h>
#include <linux/utsname.h>
#include <linux/rtc.h>
#include <linux/crc16.h>
#include <linux/kallsyms.h>
#include <linux/qpnp/qpnp-power-on.h>

#include "last_shared.h"
#include "printk_i.h"
#include "last_kmsg.h"
#include "last_tz.h"
#include "last_rpm.h"
#include "panic_reason_pon.h"

u32 xbl_copied_flg = KERN_MAGIC_FOR_XBL;

/************************************************************
*
* Function about NOW
*
************************************************************/
/* variable to collection panic info of NOW */
u16 panic_reason;
u32 panic_reason_crc = CRC16_TO_16BIT_ZERO;
u32 curr_kern_ver_crc;

static u8 fetch_rsn(void)
{
	int ret;
	u8 reg = 0;
	u8 val1, val2;

	ret = qpnp_pon_spare_reg_masked_read(
		PANIC_PON_REG1_OFFSET, PANIC_PON_REG1_MASK);
	val1 = (ret & 0xff) >> PANIC_PON_REG1_SHIFT;
	ret = qpnp_pon_spare_reg_masked_read(
		PANIC_PON_REG2_OFFSET, PANIC_PON_REG2_MASK);
	val2 = (ret & 0xff) >> PANIC_PON_REG2_SHIFT;
  val2 = (val2 >> PANIC_PON_HIGH_SHIFT);
	reg = val1 | (val2 << PANIC_PON_HIGH_SHIFT);

	pr_info("fetch_rsn=0x%x.\n", reg);
	return reg;
}

static void store_rsn(u8 val, u8 old)
{
	u8 reg1, reg2;

	if ((val & PANIC_PON_LOW_MASK) != (old & PANIC_PON_LOW_MASK)) {
		reg1 = (val & PANIC_PON_LOW_MASK);
		reg1 <<= PANIC_PON_REG1_SHIFT;
		qpnp_pon_spare_reg_masked_write(
			PANIC_PON_REG1_OFFSET, PANIC_PON_REG1_MASK, reg1);
	}

	if ((val & PANIC_PON_LOW_MASK) != (old & PANIC_PON_LOW_MASK)) {
		reg2 = (val & PANIC_PON_HIGH_MASK) >> PANIC_PON_HIGH_SHIFT;
		reg2 <<= PANIC_PON_REG2_SHIFT;
		qpnp_pon_spare_reg_masked_write(
			PANIC_PON_REG2_OFFSET, PANIC_PON_REG2_MASK, reg2);
	}
}

/*
* currently, only 0xff00 is valid and the val saved in pon reg.
*/
void set_panic_trig_rsn(u32 reason)
{
	u16 old_reason = panic_reason;
	u8 new_pon_reason, old_pon_reason;
	u16 lower_val, upper_val;
	u16 crc;
	u16 new_pri, old_pri, pri;

	new_pri = reason & REASON_PRI_MASK;
	old_pri = old_reason & REASON_PRI_MASK;
	if (old_pri >= new_pri)
		lower_val = old_reason & REASON_LOWER_BIT_MASK;
	else
		lower_val = reason & REASON_LOWER_BIT_MASK;
	upper_val = (reason | old_reason) & REASON_UPPER_BIT_MASK;
	pri = MAX(old_pri, new_pri);

	panic_reason = upper_val | lower_val | pri;
	pr_info("set_panic_trig_rsn: rsn = 0x%x from 0x%x to 0x%x\n",
			reason, old_reason, panic_reason);

	/* update data */
	crc = crc16(CRC16_START_VAL, (u8 *)(&panic_reason), sizeof(u16));
	panic_reason_crc = (crc << 16) | panic_reason;

	if (old_reason == panic_reason)
		return;

	new_pon_reason = (panic_reason & REASON_PON_MASK) >> REASON_PON_SHIFT;
	old_pon_reason = (old_reason & REASON_PON_MASK) >> REASON_PON_SHIFT;
	store_rsn(new_pon_reason, old_pon_reason);
}

static char panic_log_buf[PANIC_BUF_LEN];
u32 plog_index_crc = CRC16_TO_16BIT_ZERO;
/*
* the core function. plog_get_buf() and plog_clear()
*/
int plog_alloc_buf(int in_level, char **buf, int *len)
{
	char *p = NULL;
	u16 old_set, new_set;
	u16 crc_val;
	int level;

	level = ((in_level < PLOG_MAX_SECTION) && (in_level >= 0))
				? in_level : 0;
	p = panic_log_buf + level * PLOG_SECTION_LEN;

	/* update data */
	old_set = plog_index_crc & 0xffff;
	new_set = old_set | (1 << level);
	if (new_set != old_set) {
		crc_val = crc16(CRC16_START_VAL,
					(u8 *)(&new_set), sizeof(u16));
		plog_index_crc = (crc_val << 16) | new_set;
	}

	*buf = p;
	*len = PLOG_SECTION_LEN;
	return 0;
}

int plog_free_buf(int in_set)
{
	u16 old_set = plog_index_crc & 0xffff;
	u16 clr_set = in_set & 0xffff;
	u16 new_set;
	u16 crc_val;

	new_set = old_set & (~clr_set);
	if (new_set != old_set) {
		crc_val = crc16(CRC16_START_VAL, (u8 *)(&new_set), sizeof(u16));
		plog_index_crc = (crc_val << 16) | new_set;
	}

	return 0;
}

int plog_printk(int in_level, const char *fmt, ...)
{
	char *p = NULL;
	int len;
	int ret = 0;
	va_list args;

	plog_alloc_buf(in_level, &p, &len);

	va_start(args, fmt);
	ret = vsnprintf(p, len, fmt, args);
	va_end(args);

	return ret;
}

const char *get_rel_filename(const char *name)
{
	const char *p = strrchr(name, '/');

	return (p == NULL) ? name : p;
}

void plog_print_symbol(int level, const char *fmt, unsigned long addr)
{
	char buffer[KSYM_SYMBOL_LEN];
	char *p = NULL;
	int len;

	plog_alloc_buf(level, &p, &len);
	__check_printsym_format(fmt, "");
	sprint_symbol(buffer,
		(unsigned long)(__builtin_extract_return_addr((void *)addr)));
	snprintf(p, len, fmt, buffer);
}

void panic_reason_hook(void *p)
{
	struct panic_reason_addr_info *p_tmp = NULL;

	p_tmp = (struct panic_reason_addr_info *)p;
	p_tmp->last_panic_reason_addr = (u64)virt_to_phys(&panic_reason_crc);
	p_tmp->last_plog_index_addr = (u64)virt_to_phys(&plog_index_crc);
	p_tmp->panic_log_buf_addr = (u64)virt_to_phys(&panic_log_buf);
	p_tmp->panic_log_buf_len = PANIC_BUF_LEN;
}

/************************************************************
*
* function about LAST
*
************************************************************/
#define TYPE_SEP ('@')

/* last struct definition*/
enum {
	PR_PON_ONLY = 1,
	PR_CRC = 2,
	PR_REASON_PLOG = 3
};

enum {
	LAST_PANIC_UNINIT = 0,
	LAST_PANIC_NEW_KERN = 1,
	LAST_PANIC_PMIC_RESET = 2,
	LAST_PANIC_ADDR_WRONG = 3,
	LAST_PANIC_INIT_DONE = 8,
	LAST_PANIC_INIT_ERR = 9,
};

static int last_panic_info_status;
static u16 last_panic_reason_result;
static u8 last_pon_reason;

static u32 last_plog_index_crc;
static char *last_panic_log_ptr;
static struct panic_reason_info *last_panic_info_ptr;

int last_panic_init_status = LAST_PANIC_UNINIT;
static char *last_panic_proc_ptr;

struct panic_desc {
	char *str;
	u16 reason;
	int crashpoint_log; /*-1 - means no, 0 -default value */
	int info_log;
};

/*
* This array list all possible reason. if no, will be unknown.
* add here if a new reason found.
*/
struct panic_desc reason_arr[] = {
	/* IGNORE, new kernel version */
	/* PMIC_RESET, user long press power key to power off */
	{
		"Normal",
		TRIG_NORMAL,
		0,
		0
	},
	{
		"SHUTDOWN_FAIL",
		TRIG_SHUTDOWN_FAIL,
		0,
		PLOG_BITS_DEFAULT
	},
	{
		"WDOG_BITE",
		TRIG_WDOG_BITE,
		0,
		PLOG_BITS_DEFAULT | PLOG_WARN
	},
	{
		"SYSRQ",
		TRIG_SYSRQ_CRASH,
		PLOG_BIT_OOPS_3,
		PLOG_BITS_DEFAULT | PLOG_BITS_OOPS

	},
	{
		"OVER_TEMP",
		TRIG_OVER_TEMP,
		0,
		PLOG_BITS_DEFAULT
	},
	{
		"WDOG_BAK",
		TRIG_WDOG_BARK,
		0,
		PLOG_BITS_DEFAULT
	},
	{
		"LONG_PWR_KEY",
		TRIG_LONG_PWR_KEY,
		0,
		PLOG_BITS_DEFAULT
	},
	{
		"SUBSYS_RESET",
		TRIG_SUB_SYS_RESET,
		PLOG_BIT_SUB_SYS,
		PLOG_BIT_SUB_CRASH_POINT
	},
	{
		"OOPS",
		TRIG_OOPS,
		PLOG_BIT_OOPS_3,
		PLOG_BITS_DEFAULT | PLOG_BITS_OOPS
	},
	{
		"PANIC",
		TRIG_PANIC,
		PLOG_BIT_PANIC,
		PLOG_BITS_DEFAULT
	},
	{
		"REBOOT",
		TRIG_AP_BSP,
		PLOG_BIT_SOC,
		PLOG_BITS_DEFAULT
	},
};

static int last_init(void);
static void collect_last_addr_info(struct last_dbg_addr_info *pinfo);

static void dump_last_panic_info(void)
{
	int i;
	char *p = NULL, *q = NULL;

	pr_info("---dump last_panic_info begin---\n");
	pr_info("last_panic_info_status=%d.\n", last_panic_info_status);
	pr_info("last_pon_reason=0x%x.\n", last_pon_reason);
	pr_info("last_panic_reason_result=0x%x.\n", last_panic_reason_result);
	pr_info("last_plog_index_crc=0x%x.\n", last_plog_index_crc);
	if ((last_plog_index_crc & 0xffff) != 0) {
		for (i = 0; i < PLOG_MAX_SECTION; i++) {
			p = last_panic_log_ptr + i * PLOG_SECTION_LEN;
			if (*p == 0) /* this slot is not used */
				continue;

			q = last_panic_log_ptr + (i + 1) * PLOG_SECTION_LEN - 1;
			*q = '\0';

			pr_info("idx=%d str=%s\n", i, p);
		}
	}
	pr_info("---dump last_panic_info end---\n");
}

static void dump_last_dbg_addr_info(struct last_dbg_addr_info *p)
{
#ifdef NOT_USED_CODE
	if (p == NULL)
		return;
	pr_info("++++++++%s begin++++++++++++\n", __func__);
	pr_info("self_crc=0x%x\n",
			p->self_crc);
	pr_info("last_ver_magic=0x%x\n",
			p->last_ver_magic);
	pr_info("kern_ver_crc=0x%x\n",
			p->kern_ver_crc);
	pr_info("kern_ver_addr=0x%llx\n",
			p->kern_ver_addr);
	pr_info("xbl_copied_flg_addr=0x%llx\n",
			p->xbl_copied_flg_addr);

	pr_info("panic->last_panic_reason_addr=0x%llx\n",
			p->panic_reason_addr.last_panic_reason_addr);
	pr_info("panic->last_plog_index_addr=0x%llx\n",
			p->panic_reason_addr.last_plog_index_addr);
	pr_info("panic->panic_log_buf_addr=0x%llx\n",
			p->panic_reason_addr.panic_log_buf_addr);
	pr_info("panic->panic_log_buf_len=0x%x\n",
			p->panic_reason_addr.panic_log_buf_len);

	pr_info("lk->log_first_seq_addr=0x%llx\n",
			p->last_kmsg_addr.log_first_seq_addr);
	pr_info("lk->log_first_seq_crc16_addr=0x%llx\n",
			p->last_kmsg_addr.log_first_seq_crc16_addr);
	pr_info("lk->log_first_idx_addr=0x%llx\n",
			p->last_kmsg_addr.log_first_idx_addr);
	pr_info("lk->log_first_idx_crc16_addr=0x%llx\n",
			p->last_kmsg_addr.log_first_idx_crc16_addr);

	pr_info("lk->log_next_seq_addr=0x%llx\n",
			p->last_kmsg_addr.log_next_seq_addr);
	pr_info("lk->log_next_seq_crc16_addr=0x%llx\n",
			p->last_kmsg_addr.log_next_seq_crc16_addr);
	pr_info("lk->log_next_idx_addr=0x%llx\n",
			p->last_kmsg_addr.log_next_idx_addr);
	pr_info("lk->log_next_idx_crc16_addr=0x%llx\n",
			p->last_kmsg_addr.log_next_idx_crc16_addr);

	pr_info("lk->log_buf_addr=0x%llx\n",
			p->last_kmsg_addr.log_buf_addr);
	pr_info("lk->log_buf_len=0x%x\n",
			p->last_kmsg_addr.log_buf_len);

	pr_info("lk->tz_dbg_info.last_tz_addr=0x%llx\n",
			p->tz_dbg_info.last_tz_addr);
	pr_info("lk->tz_dbg_info.last_tz_len=0x%x\n",
			p->tz_dbg_info.last_tz_len);

	pr_info("++++++++%s end++++++++++++\n", __func__);
#endif
}

static int check_crc16(u32 in)
{
	u16 data =  in & 0xffff;
	u16 crc = ((in & 0xffff0000) >> 16);
	u16 temp = crc16(CRC16_START_VAL, (u8 *)(&data), sizeof(u16));

	if (temp != crc)
		pr_info("check_crc16 fail in=0x%x", in);
	return (temp == crc);
}

static u16 get_last_panic_reason(struct panic_reason_info *p)
{
	int status = PR_PON_ONLY;
	u16 reason = last_pon_reason << REASON_PON_SHIFT;

	if (last_panic_info_ptr == NULL) {
		status = PR_PON_ONLY;
		goto exit;
	}

	/* crc check */
	if (check_crc16(p->plog_index_crc)) {
		status = PR_REASON_PLOG;
		last_plog_index_crc = p->plog_index_crc;
	} else if (check_crc16(p->panic_reason_crc))
		status = PR_CRC;

	if (status != PR_PON_ONLY)
		reason = p->panic_reason_crc & 0xffff;

exit:
	last_panic_info_status = status;
	return reason;
}

static u16 __parse_last_panic_reason(u16 reason)
{
	u16 result = 0;
	u16 rsn_low = reason & REASON_LOWER_BIT_MASK;
	u16 rsn_high = reason & REASON_UPPER_BIT_MASK;

	if ((rsn_low == REASON_SYSRQ_CRASH) && rsn_high) {
		/*
		* SYSRQ
		* tester use this to test function
		*/
		result = TRIG_SYSRQ_CRASH;
		goto exit;
	}

	if ((rsn_low >= REASON_CMD_USER_OP_MIN)
			&& (rsn_low <= REASON_CMD_USER_OP_MAX)) {
		if (rsn_high)
			result = TRIG_NORMAL;
		else
			result = TRIG_SHUTDOWN_FAIL;
		goto exit;
	}

	if ((rsn_low >= REASON_BSP_LOW_LVL_MIN)
			&& (rsn_low <= REASON_BSP_LOW_LVL_MAX)) {
		/*
		* if lower bits is set, a special mark is set.
		* use it directly.
		*/
		result = rsn_low;
		goto exit;
	}

	if ((rsn_low >= REASON_BSP_CRI_INFO_MIN)
			&& (rsn_low <= REASON_BSP_CRI_INFO_MAX)) {
		/*
		* if lower bits is set, a special mark is set.
		* use it directly.
		*/
		result = rsn_low;
		goto exit;
	}

	/* Here, the lower bit is TRIG_INIT_STATE.
	* upper bits is used to divide more
	*/
	if (rsn_high & TRIG_OOPS) {
		/* the oops, in fact, most software errors are this type */
		result = TRIG_OOPS;
	} else if (rsn_high & TRIG_PANIC) {
		/* the panic , call panic() directly */
		result = TRIG_PANIC;
	} else if (rsn_high & TRIG_AP_BSP) {
		/* CPU driver is called */
		result = TRIG_AP_BSP;
	} else {
		result = TRIG_WDOG_BITE;
	}

exit:
	last_panic_reason_result = result;
	return result;
}

static int print_last_plog_by_idx
	(char *buf, int buf_len, int log_idx, char separator)
{
	int ret = -1, len = 0, needlen = 0;
	char *p = NULL;

	if (buf_len <= 0)
		return 0;

	p = last_panic_log_ptr + log_idx * PLOG_SECTION_LEN;
	len = MIN(buf_len, PLOG_SECTION_LEN);
	needlen = snprintf(NULL, 0, "%s%c", p, separator);
	if (needlen <= len)
		ret = snprintf(buf, len, "%s%c", p, separator);
	if (strlen(buf) == 1) {
		buf[0] = '\0';
		ret = 0;
	}

	return ret;
}

static int print_last_plog_by_set(char *buf, int len, u16 info_set)
{
	int i, ret, total;
	u16 index = 0;
	char sep;

	index = info_set;
	sep = ';';
	i = 0;
	total = 0;
	while (index) {
		if (index & 0x1) {
			ret = print_last_plog_by_idx(buf + total,
					len - total, i, sep);
			total += ret;
		}
		if (total >= len)
			break;
		i++;
		index >>= 1;
	};

	if (total >= 1) {
		total -= 1;
		buf[total] = '\0';
	}
	return total;
}

static int print_last_crashpoint(char *buf, int len, u16 set)
{
	return print_last_plog_by_set(buf, len, set);
}

static int print_last_plog_info(char *buf, int len, u16 set)
{
	return print_last_plog_by_set(buf, len, set);
}

static int handle_last_panic_reason
	(char *buf, int buf_len, u16 reason, int info_sts)
{
	unsigned int arr_sz = ARRAY_SIZE(reason_arr);
	struct panic_desc *pdesc = NULL;
	char *p = buf;
	int i, ret, total;
	u8 r1, r2;

	for (i = 0; i < arr_sz ; i++) {
		r1 = reason_arr[i].reason & REASON_PON_MASK;
		r2 = reason & REASON_PON_MASK;
		if (r1 == r2) {
			pdesc = &reason_arr[i];
			break;
		}
	}
	if (pdesc == NULL) {
		ret = snprintf(p, buf_len, "UNKNOWN%c0x%x%c",
				TYPE_SEP, reason, TYPE_SEP);
		total = ret;
		goto exit;
	}

	/* panic type */
	ret = snprintf(p, buf_len, "%s", pdesc->str);
	total = ret;
	if (info_sts != PR_REASON_PLOG)
		goto exit;

	/* crashpoint */
	ret = snprintf(p + total, buf_len - total, "%c", TYPE_SEP);
	total += 1;
	if (pdesc->crashpoint_log) {
		ret = print_last_crashpoint(p + total,
				buf_len - total,
				pdesc->crashpoint_log);
		total += ret;
	}
	/* info */
	ret = snprintf(p + total, buf_len - total, "%c", TYPE_SEP);
	total += 1;
	if (pdesc->info_log) {
		ret = print_last_plog_info(p + total,
				buf_len - total,
				pdesc->info_log);
		total += ret;
	}

exit:
	return total;
}

static int last_panic_reason_init(void)
{
	int ret;
	u16 reason;

	reason = get_last_panic_reason(last_panic_info_ptr);
	reason = __parse_last_panic_reason(reason);

	last_panic_proc_ptr = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (last_panic_proc_ptr == NULL)
		return -ENOMEM;

	ret = handle_last_panic_reason(last_panic_proc_ptr,
				PAGE_SIZE, reason, last_panic_info_status);

	return ret;
}

bool is_pmic_reset(void)
{
	return (last_pon_reason == 0);
}

static bool is_addr_info_valid(struct last_dbg_addr_info *p_addr)
{
	u8 *p = NULL;
	int len;
	u32 crc;

	p = (u8 *)p_addr + sizeof(u64);
	len = sizeof(struct last_dbg_addr_info) - sizeof(u64);
	crc = calc_crc32(p, len);

	if (crc != p_addr->self_crc) {
		pr_err("crc=%u p_addr->self_crc=%u len=%d",
				crc, p_addr->self_crc, len);
	}
	return (crc == p_addr->self_crc);
}

static bool is_new_kern(struct last_dbg_addr_info *p_addr)
{
	return ((p_addr->last_ver_magic != LAST_VERSION_MAGIC)
			|| (p_addr->kern_ver_crc != curr_kern_ver_crc));
}

static ssize_t panic_rsn_read
	(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
	int ret;
	char *pdesc = NULL;

	if (is_pmic_reset())
		pdesc = "PMIC_RESET";
	else if (last_panic_init_status == LAST_PANIC_UNINIT)
		pdesc = "NOT_READY";
	else if (last_panic_init_status == LAST_PANIC_NEW_KERN)
		pdesc = "NEW_KERN";
	else
		pdesc = last_panic_proc_ptr;

	ret = simple_read_from_buffer(buf, len, offset,
					pdesc, strlen(pdesc));

	return ret;
}

static ssize_t panic_rsn_write
	(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
	pr_info("input fmt=%s", buf);
	dump_last_panic_info();

	return len;
}

static long panic_rsn_ioctl
	(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;
	void *p = NULL;

	switch (cmd) {
	case SET_LAST_PANIC_LOG_DATA: {
		if (last_panic_log_ptr != NULL)
			return 0;

		p = kmalloc(PANIC_BUF_LEN, GFP_KERNEL);
		if (p == NULL)
			return -ENOMEM;

		ret = copy_from_user(p, (void *)arg, PANIC_BUF_LEN);
		if (ret) {
			pr_err("%s: Error copying data\n", __func__);
			return -EFAULT;
		}
		last_panic_log_ptr = p;
		return 0;
	}

	case SET_LAST_PANIC_LOG_INFO: {
		if (last_panic_info_ptr != NULL)
			return 0;

		p = kmalloc(sizeof(struct panic_reason_info), GFP_KERNEL);
		if (p == NULL)
			return -ENOMEM;

		ret = copy_from_user(p, (void *)arg,
				sizeof(struct panic_reason_info));
		if (ret) {
			pr_err("%s: Error copying data\n", __func__);
			return -EFAULT;
		}
		last_panic_info_ptr = p;
		return 0;
	}

	case LAST_PANIC_REASON_INIT: {
		/* run once */
		if (last_panic_init_status != LAST_PANIC_UNINIT)
			return 0;

		ret = last_panic_reason_init();
		last_panic_init_status = (ret >= 0)
					? LAST_PANIC_INIT_DONE
					: LAST_PANIC_INIT_ERR;
		/*
		* if last info is valid, do last_kmsg init
		* or only init panic reason.
		*/
		if (last_panic_info_ptr && last_panic_log_ptr)
			ret = last_init();

		return ret;
	}

	case GET_PANIC_REASON_ADDR_INFO: {
		struct last_dbg_addr_info info;

		collect_last_addr_info(&info);
		ret = copy_to_user((void *)arg, &info,
					sizeof(struct last_dbg_addr_info));

		if (ret) {
			pr_err("%s: Error copying data\n", __func__);
			return -EFAULT;
		}
		return 0;
	}

	case GET_PANIC_REASON_STATUS: {
		if (is_pmic_reset()) {
			last_panic_init_status = LAST_PANIC_PMIC_RESET;
			return 1;
		}

		/* get address */
		p = kmalloc(sizeof(struct last_dbg_addr_info), GFP_KERNEL);
		if (p == NULL)
			return -ENOMEM;

		ret = copy_from_user(p, (void *)arg,
					sizeof(struct last_dbg_addr_info));
		if (ret) {
			pr_err("%s: Error copying data\n", __func__);
			return -EFAULT;
		}
		dump_last_dbg_addr_info(p);

		/* check */
		if (!is_addr_info_valid(p)) {
			last_panic_init_status = LAST_PANIC_ADDR_WRONG;
			ret = 2;
		} else if (is_new_kern(p)) {
			last_panic_init_status = LAST_PANIC_NEW_KERN;
			ret = 2;
		} else {
			ret = 0;
		}

		if (ret != 0) {
			pr_info("last_panic_init_status=%d\n",
				last_panic_init_status);
		}
		kfree(p);
		return ret;
	}

	default:
		pr_err("ioctl is not support\n");
		return -EINVAL;
	}

	return 0;
}

static const struct file_operations panic_rsn_file_ops = {
	.owner = THIS_MODULE,
	.read = panic_rsn_read,
	.write = panic_rsn_write,
	.unlocked_ioctl = panic_rsn_ioctl,
};

static int __init panic_reason_init(void)
{
	/* read panic_reason */
	last_pon_reason = fetch_rsn();
	set_panic_trig_rsn(TRIG_INIT_STATE);

	curr_kern_ver_crc = calc_crc32(linux_banner, strlen(linux_banner));
	proc_create("lst_pnc_rsn", S_IRUGO|S_IWUGO, NULL, &panic_rsn_file_ops);

	pr_info("last magic %u ready.\n", LAST_VERSION_MAGIC);
	return 0;
}

module_init(panic_reason_init);

static int last_init(void)
{
	last_kmsg_init();
	/* If want to add function, add code here */
	last_tz_dbgfs_init();
	last_rpm_dbgfs_init();
	return 0;
}

static void collect_last_addr_info(struct last_dbg_addr_info *pinfo)
{
	char *p = NULL;
	int len = 0;

	panic_reason_hook(&pinfo->panic_reason_addr);
	last_kmsg_info_hook(&pinfo->last_kmsg_addr);
	/* If want to add function, add code here */
	last_tz_addr_hook(&pinfo->tz_dbg_info);
	last_rpm_addr_hook(&pinfo->rpm_dbg_info);

	pinfo->last_ver_magic = LAST_VERSION_MAGIC;
	pinfo->kern_ver_crc = curr_kern_ver_crc;
	pinfo->kern_ver_addr = (u64)virt_to_phys(linux_banner);
	pinfo->xbl_copied_flg_addr = (u64)virt_to_phys(&xbl_copied_flg);

	p = (char *)pinfo + sizeof(u64);
	len = sizeof(struct last_dbg_addr_info) - sizeof(u64);
	pinfo->self_crc = calc_crc32(p, len);

	dump_last_dbg_addr_info(pinfo);
}
