#ifndef __CJSON_H
#define __CJSON_H

#include <sys/ioctl.h>

#define SEMS_DEVICE_TYPE (21)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
	SEMS_ID_MIN = 0x10,
	SEMS_AUDIO_ID = SEMS_ID_MIN,
	SEMS_VIDEO_ID,
	SEMS_SENSOR_ID,
	SEMS_FP_ID,
	SEMS_USB_ID,
	SEMS_TP_ID,
	SEMS_LCD_ID,
	SEMS_UFS_ID,
	SEMS_BATT_ID,
	SEMS_ID_MAX,
};

union json_val {
	int valueint;
	long valuelong;
	char *valuestring;
};

/* The cJSON structure: */
struct json_obj {
	struct json_obj *next;
	struct json_obj *child;
	int type;
	char *string;
	union json_val val;
};

#define SEMS_UEVENT_MAX_LEN (900)
#define SEMS_IS_DEVICE_EN _IOWR('s', 0x85, int)
#define SEMS_CRT_JSON_OBJ _IO('s', 0x84)
#define SEMS_SEND_JSON _IO('s', 0x83)
#define SEMS_BUF_LEN (1024)

#define FILE_SEMS_NODE ("/dev/sems")

long system_current_time_millis(void);
int is_sems_enable(int id);
char *get_sems_dev_name(int dev_id);
struct json_obj *json_crt_object(void);
void json_add_null(struct json_obj *object, const char *name);
void json_add_nr_int(
				struct json_obj *object, const char *name, int number);
void json_add_nr_long(
				struct json_obj *object, const char *name, long number);
void json_add_time(struct json_obj *object, long time);
void json_add_string(struct json_obj *object,const char *name, char *string);
void  json_add_child(struct json_obj *object, const char *name, struct json_obj *item);
int send_json(struct json_obj *object, int sems_id);
#endif
