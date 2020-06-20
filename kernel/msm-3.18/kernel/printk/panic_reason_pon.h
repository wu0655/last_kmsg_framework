#ifndef __PANIC_REASON_PON_H__
#define __PANIC_REASON_PON_H__

#include <linux/panic_reason.h>

#define PANIC_PON_LOW_MASK (0x7f)
/*#define PANIC_PON_VAL1_SHIFT (0)*/
#define PANIC_PON_HIGH_MASK (0x80)
#define PANIC_PON_HIGH_SHIFT (7)

/*
* PLOG---panic_log
* 4K memory is devided into 16 slots.
* each slot is for one level
*/
#define PANIC_BUF_LEN (PAGE_SIZE)
#define PLOG_MAX_SECTION (1 << 4)
#define PLOG_SECTION_LEN (PANIC_BUF_LEN >> 4)

#define SET_LAST_PANIC_LOG_DATA _IO('P', 1)
#define SET_LAST_PANIC_LOG_INFO _IO('P', 2)
#define GET_PANIC_REASON_ADDR_INFO _IO('P', 3)
#define LAST_PANIC_REASON_INIT _IO('P', 4)
#define GET_PANIC_REASON_STATUS _IO('P', 5)

#define MIN(a, b)                   (((a) < (b)) ? (a) : (b))
#endif
