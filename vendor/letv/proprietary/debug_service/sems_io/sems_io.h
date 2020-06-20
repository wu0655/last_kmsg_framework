#ifndef __CJSON_H
#define __CJSON_H

#include <sys/ioctl.h>

#include "sems_type.h"

#define SEMS_DEVICE_TYPE (21)
#define SEMS_DEV_NAME_MAX_LEN (16)

#define SEMS_UEVENT_MAX_LEN (900)
#define SEMS_GET_DEVICE_NAME _IO('s', 0x85)
#define SEMS_CRT_JSON_OBJ _IO('s', 0x84)
#define SEMS_SEND_JSON _IO('s', 0x83)
#define SEMS_BUF_LEN (1024)

#define FILE_SEMS_NODE ("/dev/sems")

long system_current_time_millis(void);
int get_sems_dev_name(int dev_id, char *name);
int sems_send_buf(char *buf, int len, int sems_id);
#endif
