#ifndef __LAST_RPM_HEAD__
#define __LAST_RPM_HEAD__

#define RPM_ULOG_MAX_NAME_SIZE 23

#define RPM_ULOG_TRANSPORT_RAM  0
#define RPM_ULOG_TRANSPORT_STM  1
#define RPM_ULOG_TRANSPORT_ALTERNATE 2

// Error Codes that can be returned from RPM_ULog functions.
typedef enum
{
  RPM_ULOG_ERROR = -1,
  RPM_ULOG_SUCCESS,
  RPM_ULOG_ERR_BUFFER_TOO_SMALL,
  RPM_ULOG_ERR_INVALIDNAME,
  RPM_ULOG_ERR_ALREADYCREATED,
  RPM_ULOG_ERR_ALREADYENABLED,
  RPM_ULOG_ERR_INVALIDHANDLE,
  RPM_ULOG_ERR_INITINCOMPLETE,
  RPM_ULOG_FAST_TO_RAM_UNAVAIL,
  RPM_ULOG_FAST_TO_RAM_FAIL,
  RPM_ULOG_FAST_TO_RAM_SUCCESS,
} rpm_ULogResult;

struct rpm_ext_log
{
  uint32 cfg;
  uint32 timestamp_lo;
  uint32 timestamp_hi;
  uint32 id;
  uint32 p0;
  uint32 p1;
  uint32 p2;
  uint32 p3;
};

struct RPM_ULOG_STRUCT
{
  struct RPM_ULOG_STRUCT *next;
  uint32 version;
  char name[RPM_ULOG_MAX_NAME_SIZE+1];
  uint32 logStatus;
  char *buffer;
  uint32 bufSize;
  uint32 bufSizeMask;
  volatile uint32 read;
  volatile uint32 readFlags;
  volatile uint32 write;
  volatile uint32 readWriter;
  uint32 usageData;
  uint32 transactionWriteCount;
  uint32 transactionWriteStart;
  unsigned char transport;
  unsigned char protocol_num;
  unsigned char feature_flags1;
  unsigned char resetCount;
  uint32 stmPort;
  uint32 *preserve;
} ;

int  last_rpm_dbgfs_init(void);
void last_rpm_addr_hook(struct rpm_dbg_addr_info *p);
#endif
