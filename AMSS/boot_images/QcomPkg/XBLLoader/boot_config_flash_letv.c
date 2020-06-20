/*===================================================
move the function from LK to sbl.
The TZ will zero all memory exception area in white
list, so we MUST copy last_kmsg out before TZ and
add the memory area to while list of TZ
====================================================
*/
#include "boot_logger.h"
#include "boot_flash_dev_if.h"
#include "boot_flash_target.h"
#include "boot_dload_debug.h"
#include "boot_sdcc.h"
#include "boot_extern_hotplug_interface.h"
#include "boot_visual_indication.h"
#include "boot_util.h"
#include "boot_config_flash_letv.h"
#include "boot_extern_pmic_interface.h"
#include "boot_shared_functions_consumer.h"
#include "boot_extern_smem_interface.h"
#include "smem_type.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

//#define DEBUG_LK
#define PMIC_A_DEVICE_ID   0

/*================================================
**  global variable
**================================================
*/
/* letvconfig4 partition ID */
extern uint8 kernellog_partition_id[];
extern pm_err_flag_type pm_pon_set_spare_reg_data
(
	uint32 pmic_device_index,
	pm_pon_spare_reg_type spare_reg,
	uint8 fsm
);
extern pm_err_flag_type pm_pon_get_spare_reg_data
(
	uint32 pmic_device_index,
	pm_pon_spare_reg_type spare_reg,
	uint8 *fsm
);

#define ALWAYS 0
#define INFO 1
#define SPEW 2
#define DEBUGLEVEL 1
#define BUF_LEN (64)
#define LOG_TAG "last:xbl "

#if (SPEW <= DEBUGLEVEL)
#define LELOGD(...) (letv_printf(LOG_TAG, __VA_ARGS__))
#else
#define LELOGD(...)
#endif

#if (INFO <= DEBUGLEVEL)
#define LELOGI(...) (letv_printf(LOG_TAG, __VA_ARGS__))
#else
#define LELOGI(...)
#endif

#if (ALWAYS <= DEBUGLEVEL)
#define LELOGE(...) (letv_printf(LOG_TAG, __VA_ARGS__))
#else
#define LELOGE(...)
#endif

int letv_printf(const char *tag, const char *fmt, ...)
{
	int ret = 0, len = 0;
	char buf[BUF_LEN];

	len = snprintf(buf, BUF_LEN, "%s", tag);
	va_list ap;
	va_start(ap, fmt);
	ret = vsnprintf(buf+len, BUF_LEN, fmt, ap);
	va_end(ap);

	boot_log_message(buf);
	return ret;
}

static int reflect
(
int data,
const uint32 len
)
{
	int ref = 0;
	uint32 i;

	for(i=0; i < len; i++) {
		if(data & 0x1) {
			ref |= (1 << ((len - 1) - i));
		}
		data = (data >> 1);
	}

	return ref;
}

/*===========================================================================

FUNCTION  calc_crc32

DESCRIPTION
  This function calculate CRC32 on input data.

DEPENDENCIES
  None

RETURN VALUE
  Returns CRC32 of given data

SIDE EFFECTS
  None

===========================================================================*/
static uint32 calc_crc32
(
  const uint8   *data_in,
  const uint32  nbytes_in
)
{
	uint32 k = 8;                   // length of unit (i.e. byte)
	int MSB = 0;
	int gx = 0x04C11DB7;         // IEEE 32bit polynomial
	int regs = 0xFFFFFFFF;       // init to all ones
	int regsMask = 0xFFFFFFFF;   // ensure only 32 bit answer
	int regsMSB = 0;
	uint32 i, j;
	uint8 DataByte;

	if ( (data_in == NULL) || (nbytes_in == 0) )
		return 0;

	for( i=0; i < nbytes_in; i++) {
		DataByte = data_in[i];
		DataByte = reflect(DataByte,8);
		for(j=0; j < k; j++) {
			MSB = DataByte >> (k-1);  // get MSB
			MSB &= 1;                 // ensure just 1 bit
			regsMSB = (regs>>31) & 1; // MSB of regs
			regs = regs<<1;           // shift regs for CRC-CCITT
			if(regsMSB ^ MSB) {       // MSB is a 1
				regs = regs ^ gx;       // XOR with generator poly
		}
		regs = regs & regsMask;   // Mask off excess upper bits
		DataByte <<= 1;           // get to next bit
		}
	}

	regs = regs & regsMask;       // Mask off excess upper bits
	return reflect(regs,32) ^ 0xFFFFFFFF;
}

void letv_write_data_to_partition
(
	uint8* buf,
	uint64 data_offsets,
	uint32 size
)
{
	boot_boolean success = FALSE;
	success = dev_sdcc_write_bytes(buf, data_offsets, size, GEN_IMG);
	BL_VERIFY(success, BL_ERR_SBL);
}

extern const int path_id[];
void letv_read_data_from_partition
(
	uint8* buf,
	uint64 data_offsets,
	uint32 size
)
{
	boot_boolean success = FALSE;
	int16 hotplug_id;
	hotplug_id = path_id[(uint16)GEN_IMG];
	success = dev_sdcc_read_bytes(buf, data_offsets, size, hotplug_id);
	BL_VERIFY(success, BL_ERR_SBL);
}
static void get_pon_poff_info(struct pon_poff_info *p)
{
	p->reset_status_reg = sbl1_hw_get_reset_status();
	boot_pm_dev_get_power_on_reason(0, &(p->pm0));
	boot_pm_dev_get_power_on_reason(1, &(p->pm1));
}

static void get_panic_reason_info
(
	struct panic_reason_addr_info *p_addr,
	struct panic_reason_info *p
)
{
#if 0
	memcpy(&(p->panic_reason), (void*)(p_addr->last_panic_reason_addr), sizeof(uint32));
#else
	p->panic_reason_crc = *((u32*)(p_addr->last_panic_reason_addr));
	p->plog_index_crc = *((u32*)(p_addr->last_plog_index_addr));
#endif
}

static void get_last_kmsg_info
(
	struct last_kmsg_addr_info *p_addr,
	struct last_kmsg_info *p
)
{
#if 0
	/* copy last_kmsg info from struct */
	memcpy(&(p->log_first_idx),(void*)(p_addr->log_first_idx_addr), sizeof(uint32));
	memcpy(&(p->log_first_seq),(void*)(p_addr->log_first_seq_addr), sizeof(uint64));
	memcpy(&(p->log_next_idx), (void*)(p_addr->log_next_idx_addr), sizeof(uint32));
	memcpy(&(p->log_next_seq), (void*)(p_addr->log_next_seq_addr), sizeof(uint64));
	memcpy(&(p->log_first_seq_crc16), (void*)(p_addr->log_first_seq_crc16_addr), sizeof(u16));
	memcpy(&(p->log_first_idx_crc16), (void*)(p_addr->log_first_idx_crc16_addr), sizeof(u16));
	memcpy(&(p->log_next_seq_crc16), (void*)(p_addr->log_next_seq_crc16_addr), sizeof(u16));
	memcpy(&(p->log_next_idx_crc16), (void*)(p_addr->log_next_idx_crc16_addr), sizeof(u16));
#else
	p->log_first_idx = *((u32*)(p_addr->log_first_idx_addr));
	p->log_first_seq = *((u64*)(p_addr->log_first_seq_addr));
	p->log_next_idx = *((u32*)(p_addr->log_next_idx_addr));
	p->log_next_seq = *((u64*)(p_addr->log_next_seq_addr));
	p->log_first_seq_crc16 = *((u16*)(p_addr->log_first_seq_crc16_addr));
	p->log_first_idx_crc16 = *((u16*)(p_addr->log_first_idx_crc16_addr));
	p->log_next_seq_crc16 = *((u16*)(p_addr->log_next_seq_crc16_addr));
	p->log_next_idx_crc16 = *((u16*)(p_addr->log_next_idx_crc16_addr));
#endif
}


/*================================================
*
**  Function :  is_match_ver
*
** ================================================
*/
/*!
*
* @brief
* compare kernel version information in ram and in struct last_dbg_addr_info
* if match, means we last_kmsg information is valid.
* or, not valid.
*/
boolean is_match_ver(struct last_dbg_addr_info *p_addr)
{
	u32 kern_ver_crc;
	char buff[KERN_VER_LEN];
	boolean ret = FALSE;
	int len;

	if (p_addr->last_ver_magic != LAST_VERSION_MAGIC) {
		LELOGE("last version of xbl doesn't match with kernel");
		return FALSE;
	}

	memcpy(buff, (void*)(p_addr->kern_ver_addr), KERN_VER_LEN);
	len = MIN(strlen(buff), KERN_VER_LEN);
	kern_ver_crc = calc_crc32((uint8 *)buff, strlen(buff));

	ret = (kern_ver_crc == p_addr->kern_ver_crc);
	return ret;
}

boolean is_copied_ramdump(struct last_dbg_addr_info *p_addr)
{
	struct last_dbg_addr_info *p = p_addr;
	boolean ret = FALSE;
	u32 kern_magic = -1;

	kern_magic = *((u32*)(p->xbl_copied_flg_addr));
	if (kern_magic != KERN_MAGIC_FOR_XBL) {
		ret = TRUE;
	} else {
		*((u32*)(p->xbl_copied_flg_addr)) = 0;
		ret = FALSE;
	}

	return ret;
}

boolean is_addr_info_valid(struct last_dbg_addr_info *p_addr)
{
	uint8 *p = NULL;
	int len;
	uint32 crc;

	p = (uint8 *)p_addr + sizeof(uint64);
	len = sizeof(struct last_dbg_addr_info) - sizeof(uint64);
	crc = calc_crc32(p, len);

	if (crc != p_addr->self_crc) {
		LELOGE("crc=%u p_addr->self_crc=%u.", crc, p_addr->self_crc);
	}
	return (crc == p_addr->self_crc);
}

/*================================================
*
**  Function :  is_ign_bootup
*
** ================================================
*/
/*!
*
* @brief
* if a reset is not warm reset and hard reset, it should be a cold reset.
*	but only PON and RTC are normal.
* A S3 reset should also be taken as a normal cold boot. for it's the
* 	workaround for this deug function.
* ref document:
*/
boolean is_ign_bootup(void)
{
	uint8 reg1, reg2;
	pm_pon_get_spare_reg_data(0, PM_PON_XVDD_RB_SPARE, &reg1);
	pm_pon_get_spare_reg_data(0, PM_PON_XVDD_RB_SPARE, &reg2);

	return ((reg1 | reg2) == 0);
}

#define PROP_VALUE_MAX 92

boolean do_copy_info( void )
{
	struct last_dbg_info info;
	struct last_dbg_addr_info info_addr;
	boolean ret = FALSE;
	boot_flash_trans_if_type *trans_if = NULL;

	int len1=0;
	int len2=0;
	char version_prop1[PROP_VALUE_MAX+1]={0};
	char version_prop2[PROP_VALUE_MAX+1]={0};
	char *tmp1 = NULL;
	char *tmp2 = NULL;

	boot_flash_configure_target_image(kernellog_partition_id);
	trans_if = boot_flash_dev_open_image(GEN_IMG);

	if (trans_if == NULL)
	{
		LELOGE("%d", __LINE__);
		return ret;
	}

	/* Read the lk_headaer */
	boot_clobber_add_local_hole(boot_flash_trans_get_clobber_tbl_ptr(trans_if),
							(void *)&info_addr,
							sizeof(struct last_dbg_addr_info));
	ret = boot_flash_trans_read(trans_if, (void *)&info_addr,
							LAST_DBG_INFO_OFFSET + LAST_DBG_HEAD_ADDR_OFFSET,
							sizeof(struct last_dbg_addr_info));
	if (ret == FALSE)
	{
		LELOGE("%d", __LINE__);
		goto exit;
	}

	ret = is_addr_info_valid(&info_addr);
	if (ret == FALSE)
	{
		LELOGI("%d", __LINE__);
		goto exit;
	}

	ret = is_match_ver(&info_addr);
	if (ret == FALSE)
	{
		LELOGI("%d", __LINE__);
		goto exit;
	}

	ret = is_copied_ramdump(&info_addr);
	if (ret == TRUE)
	{
		LELOGI("%d", __LINE__);
		goto exit;
	}

	LELOGD("%d", __LINE__);
	get_panic_reason_info(&info_addr.panic_reason_addr, &info.panic_info);
	get_last_kmsg_info(&info_addr.last_kmsg_addr, &info.last_kmsg);
	get_pon_poff_info(&info.pon_poff);
	info.status = sizeof(struct last_dbg_info); 	/* use size as status */
	LELOGD("%d", __LINE__);

	if (info_addr.last_kmsg_addr.log_buf_len > LAST_INFO_MAX_LEN)
		goto exit;

	letv_read_data_from_partition((uint8 *)(&len1), LAST_VER_INF_BUF_OFFSET, sizeof(int));
	if(len1<(PROP_VALUE_MAX+1))
	{
		letv_read_data_from_partition((uint8 *)(&version_prop1), LAST_VER_INF_BUF_OFFSET+sizeof(int), len1);
		LELOGE("version info %s", version_prop1);
		letv_read_data_from_partition((uint8 *)(&len2), LAST_VER_INF_BUF_OFFSET+len1+sizeof(int), sizeof(int));
		if(len2<(PROP_VALUE_MAX+1))
		{
			letv_read_data_from_partition((uint8 *)(&version_prop2), LAST_VER_INF_BUF_OFFSET+len1+2*sizeof(int), len2);
			tmp1 = boot_smem_alloc(SMEM_ID_VENDOR1, len1);//use this smem indext to same the version prop info.
			tmp2 = boot_smem_alloc(SMEM_ID_VENDOR2, len2);
			if(tmp1 != NULL && tmp2!=0)
			{
				memcpy((void*)tmp1, (void *)(&version_prop1), len1);
				memcpy((void*)tmp2, (void *)(&version_prop2), len2);
			}
			else
			{
				LELOGE("%d", __LINE__);
			}
		}
		else
		{
			LELOGE("%d", __LINE__);
		}
	}
	else
	{
		LELOGE("%d", __LINE__);
	}

	letv_write_data_to_partition((uint8 *)(info_addr.last_kmsg_addr.log_buf_addr),
							LAST_DBG_INFO_OFFSET,
							info_addr.last_kmsg_addr.log_buf_len);

	letv_write_data_to_partition((uint8 *)(info_addr.panic_reason_addr.panic_log_buf_addr),
							LAST_DBG_INFO_OFFSET + LAST_PANIC_LOG_BUF_OFFSET,
							info_addr.panic_reason_addr.panic_log_buf_len);

	letv_write_data_to_partition((uint8 *)&info,
							LAST_DBG_INFO_OFFSET + LAST_DBG_HEAD_OFFSET,
							sizeof(struct last_dbg_info));

	letv_write_data_to_partition((uint8 *)(info_addr.tz_dbg_info.last_tz_addr),
							LAST_DBG_INFO_OFFSET + LAST_TZ_LOG_BUF_OFFSET,
							info_addr.tz_dbg_info.last_tz_len);

	LELOGE("%lx  %d", info_addr.rpm_dbg_info.last_rpm_cfg_addr, info_addr.rpm_dbg_info.last_rpm_cfg_len);

	letv_write_data_to_partition((uint8 *)(info_addr.rpm_dbg_info.last_rpm_cfg_addr),
							LAST_DBG_INFO_OFFSET + LAST_RPM_CFG_BUF_OFFSET,
							info_addr.rpm_dbg_info.last_rpm_cfg_len);

	LELOGE("%lx  %d", info_addr.rpm_dbg_info.last_rpm_addr, info_addr.rpm_dbg_info.last_rpm_len);
	letv_write_data_to_partition((uint8 *)(info_addr.rpm_dbg_info.last_rpm_addr),
							LAST_DBG_INFO_OFFSET + LAST_RPM_LOG_BUF_OFFSET,
							info_addr.rpm_dbg_info.last_rpm_len);
	ret = TRUE;

exit:
	/* Release the translation layer resource */
	boot_flash_dev_close_image(&trans_if);
	if (ret)
		LELOGI("OK");
	else
		LELOGI("FAIL");

	return ret;
}

/*================================================
*
**  Function :  boot_copy_last_debug_info
*
** ================================================
*/
/*!
*
* @brief
* copy last_debug_information from memory to a partition
*/
void boot_copy_last_debug_info( bl_shared_data_type *bl_shared_data )
{
	if (! is_ign_bootup())
	{
		do_copy_info();
	}

	return;
}
