#ifndef __LAST_KMSG_HEAD__
#define __LAST_KMSG_HEAD__

#include "last_shared.h"

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

enum {
	LASK_KMSG_UNINIT = -1,
	LAST_KMSG_GOOD = 0,
	LAST_KMSG_CRC_ALL_ERROR = 1,
	LAST_KMSG_CRC_ERROR = 2,
	LAST_KMSG_SCAN_FAIL = 3,
};
uint32 calc_crc32(const uint8 *data_in, const uint32 nbytes_in);
int last_kmsg_init(void);
int  last_tz_dbgfs_init(void);
void last_kmsg_info_hook(struct last_kmsg_addr_info *p);

#define SET_LK_LOG_DATA _IO('L', 1)
#define SET_LK_LOG_INFO _IO('L', 2)
#define SET_LK_PON_POFF_INFO _IO('L', 3)
#define LK_POST_INIT _IO('L', 4)
#define GET_LK_LAST_INFO_ADDR _IO('L', 5)

#define SET_TZ_LOG_DATA _IO('L', 1)

#define SET_RPM_CFG_DATA _IO('L', 1)
#define SET_RPM_LOG_DATA _IO('L', 2)
#endif
