#ifndef __LAST_LETV_DEBUG_H_H__
#define __LAST_LETV_DEBUG_H_H__

/*================================================
**  definition for last_debug module
**  The 2 files should be nearly the same:
**  letv_last_debug.h----XBL
**  last_shared.h ---KERNEL
**================================================
*/

#define PANIC_PON_REG1_OFFSET PM_PON_XVDD_RB_SPARE
#define PANIC_PON_REG2_OFFSET PM_PON_SOFT_RB_SPARE

typedef uint8 u8;
typedef uint16 u16;
typedef uint32 u32;
typedef uint64 u64;
#define BIT(x)   (UINT8) (1 << (x))

#define KERN_MAGIC_FOR_XBL (0x55aaaa55)
#define KERN_VER_LEN (256)


/* the UFS paritition will be divided into several parts.
* last_kmsg is the first.
*/
#define SEC_GAP (0x1000)
#define LAST_DBG_INFO_OFFSET (0x0)
#define LAST_DBG_INFO_SIZE (0x100000)

/*last debug offset info in debug parition*/
#define LAST_DBG_MEM_LEN LAST_DBG_INFO_SIZE

#define LAST_DBG_HEAD_MAX_LEN (0x1000)
#define LAST_DBG_HEAD_OFFSET (LAST_DBG_MEM_LEN - LAST_DBG_HEAD_MAX_LEN)

#define LAST_DBG_HEAD_ADDR_MAX_LEN (0x1000)
#define LAST_DBG_HEAD_ADDR_OFFSET \
			(LAST_DBG_HEAD_OFFSET-LAST_DBG_HEAD_ADDR_MAX_LEN)

#define LAST_PANIC_LOG_MAX_LEN (0x2000)
#define LAST_PANIC_LOG_BUF_OFFSET \
			(LAST_DBG_HEAD_ADDR_OFFSET-LAST_PANIC_LOG_MAX_LEN)

#define LAST_TZ_LOG_MAX_LEN (0x2000)
#define LAST_TZ_LOG_BUF_OFFSET \
			(LAST_PANIC_LOG_BUF_OFFSET - LAST_TZ_LOG_MAX_LEN)

#define LAST_RPM_LOG_MAX_LEN (0x2000)
#define LAST_RPM_LOG_BUF_OFFSET \
			(LAST_TZ_LOG_BUF_OFFSET - LAST_RPM_LOG_MAX_LEN)

#define LAST_RPM_CFG_MAX_LEN (0x200)
#define LAST_RPM_CFG_BUF_OFFSET \
			(LAST_RPM_LOG_BUF_OFFSET - LAST_RPM_CFG_MAX_LEN)

#define LAST_VER_INF_MAX_LEN (0x200)
#define LAST_VER_INF_BUF_OFFSET \
			(LAST_RPM_CFG_BUF_OFFSET - LAST_VER_INF_MAX_LEN)

#define LAST_INFO_MAX_LEN LAST_TZ_LOG_BUF_OFFSET

PACKED struct last_kmsg_info {
	/* align by 64bit?*/
	u64 log_first_seq;
	u64 log_next_seq;
	u32 log_first_idx;
	u32 log_next_idx;
	u16 log_first_seq_crc16;
	u16 log_first_idx_crc16;
	u16 log_next_seq_crc16;
	u16 log_next_idx_crc16;
};

PACKED struct last_kmsg_addr_info {
	u64 log_first_seq_addr;
	u64 log_first_seq_crc16_addr;
	u64 log_first_idx_addr;
	u64 log_first_idx_crc16_addr;
	u64 log_next_seq_addr;
	u64 log_next_seq_crc16_addr;
	u64 log_next_idx_addr;
	u64 log_next_idx_crc16_addr;
	u64 log_buf_addr;
	u32 log_buf_len;
	u32 reserved;
};

PACKED struct pon_pm_reason_status {
	u8 pon_reason1;
	u8 pon_reason2;
	u8 warm_reset_reason1;
	u8 warm_reset_reason2;
	u8 poff_reason1;
	u8 poff_reason2;
	u8 soft_reset_reason1;
	u8 soft_reset_reason2;
};

PACKED struct pon_poff_info {
	u64 pm0;
	u64 pm1;
	u32 reset_status_reg;
	u32 reserved0;
};

PACKED struct panic_reason_info {
	u32 panic_reason_crc;
	u32 plog_index_crc;
};

PACKED struct panic_reason_addr_info {
	u64 last_panic_reason_addr;
	u64 last_plog_index_addr;
	u64 panic_log_buf_addr;
	u32 panic_log_buf_len;
	u32 reserved;
};

PACKED struct tz_dbg_addr_info {
	u64 last_tz_addr;
	u32 last_tz_len;
	u32 reserved;
};

PACKED struct rpm_dbg_addr_info {
	u64 last_rpm_addr;
	u32 last_rpm_len;
	u32 last_rpm_cfg_len;
	u64 last_rpm_cfg_addr;
};


PACKED struct last_dbg_info {
	u64 status;
	struct last_kmsg_info last_kmsg;
	struct panic_reason_info panic_info;
	struct pon_poff_info pon_poff;
};

#define LAST_VERSION_MAGIC (0x12340051)
PACKED struct last_dbg_addr_info {
	u32 self_crc;
	u32 reserved;
	u32 last_ver_magic;
	u32 kern_ver_crc;
	u64 kern_ver_addr;
	u64 xbl_copied_flg_addr;
	struct panic_reason_addr_info panic_reason_addr;
	struct last_kmsg_addr_info last_kmsg_addr;
	struct tz_dbg_addr_info tz_dbg_info;
	struct rpm_dbg_addr_info rpm_dbg_info;
};
#endif
