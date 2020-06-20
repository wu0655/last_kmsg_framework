#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <cutils/properties.h>

#define LOG_TAG "cjsonlib"
#include <cutils/log.h>

#include "cJSON.h"

#define pr_err(x...) do { ALOGE(x); } while (0)
#define pr_info(x...) do { ALOGI(x); } while (0)

struct sems_dev_desc {
	int dev_id;
	char *name;
};
struct sems_dev_desc sems_dev_array[] = {
	{SEMS_AUDIO_ID, "Audio"},
	{SEMS_VIDEO_ID, "Video"},
	{SEMS_SENSOR_ID, "Sensor"},
	{SEMS_FP_ID, "FingerPrint"},
	{SEMS_USB_ID, "USB"},
	{SEMS_TP_ID, "TouchPanel"},
	{SEMS_LCD_ID, "LCD"},
	{SEMS_UFS_ID, "UFS"},
	{SEMS_BATT_ID, "Battery"},
};

char *get_sems_dev_name(int dev_id)
{
	int i;
	int arr_size = ARRAY_SIZE(sems_dev_array);;

	if ((dev_id >= SEMS_ID_MAX) || (dev_id < SEMS_ID_MIN)) {
		return NULL;
	}
	for (i = 0; i < arr_size; i++) {
		if (sems_dev_array[i].dev_id == dev_id)
			break;
	}

	return sems_dev_array[i].name;
}

struct printbuffer {
	char *buffer;
	int length;
	int offset;
};

/* cJSON Types: */
#define JSON_NULL 2
#define JSON_NR_INT 3
#define JSON_STRING 4
#define JSON_OBJECT 6
#define JSON_NR_LONG 7

static int print_string_ptr(const char *str, struct printbuffer *p);
static int print_string(struct json_obj *item, struct printbuffer *p);
static int print_object(struct json_obj *item, int depth, struct printbuffer *p);
static int print_value(struct json_obj *item, int depth, struct printbuffer *p);

static void *json_malloc(int size)
{
	return malloc(size);
}

static void *json_zalloc(int size)
{
	void *p = json_malloc(size);

	if (p != NULL)
		memset(p, 0, size);
	return p;
}

static void json_free(void *where)
{
	free(where);
}

static char* json_strdup(const char* str)
{
	return strdup(str);
}

long system_current_time_millis(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    long when = now.tv_sec * 1000LL + now.tv_usec / 1000;
    return when;
}

static void  additem_to_list(struct json_obj *array, struct json_obj *item)
{
	struct json_obj *c = array->child;
	if (!item)
		return;

	if (!c) {
		array->child=item;
	} else {
		while (c && c->next)
			c=c->next;
		c->next = item;
	}
}

static struct json_obj *json_new_item(void)
{
	struct json_obj *node = (struct json_obj*)json_zalloc(sizeof(struct json_obj));
	return node;
}

struct json_obj *json_crt_object(void)
{
	struct json_obj *item = NULL;

	item = json_new_item();
	if(item) {
		item->type = JSON_OBJECT;
	}
	return item;
}

void  json_add_child(struct json_obj *object,
				const char *name, struct json_obj *item)
{
	if (!item)
		return;
	if (item->string)
		json_free(item->string);

	item->string = json_strdup(name);
	additem_to_list(object,item);
}

static void  json_add_item
	(struct json_obj *object, struct json_obj *item)
{
	if (!item)
		return;

	additem_to_list(object, item);
}

void json_add_null(struct json_obj *object, const char *name)
{
	struct json_obj *item = json_new_item();

	if (item) {
		item->type = JSON_NULL;
		item->string = json_strdup(name);
	}
	json_add_item(object, item);
}

void json_add_nr_int(struct json_obj *object,
				const char *name, int number)
{
	struct json_obj *item = json_new_item();

	if (item) {
		item->type = JSON_NR_INT;
		item->string = json_strdup(name);
		item->val.valueint = number;
	}
	json_add_item(object, item);
}

void json_add_nr_long(struct json_obj *object,
				const char *name, long number)
{
	struct json_obj *item = json_new_item();

	if (item) {
		item->type = JSON_NR_LONG;
		item->string = json_strdup(name);
		item->val.valuelong = number;
	}
	json_add_item(object, item);
}

void json_add_time(struct json_obj *object, long time_in_ms)
{
	return json_add_nr_long(object, "exception_time", time_in_ms);
}

void json_add_string(struct json_obj *object,
				const char *name, char *string)
{
	struct json_obj *item = json_new_item();

	if (item) {
		item->type = JSON_STRING;
		item->string = json_strdup(name);
		item->val.valuestring = json_strdup(string);
	}
	json_add_item(object, item);
}

static inline char *ensure(struct printbuffer *p, int needed)
{
	needed += p->offset;
	return (needed <= p->length) ? (p->buffer + p->offset) : NULL;
}

static int write_buf_to_pb(char *buf, int len, struct printbuffer *p)
{
	char *out = NULL;

	out = ensure(p, len + 1);
	if (!out)
		return -ENOMEM;

	memcpy(out, buf, len);
	out[len] = '\0';

	p->offset += len;
	return len;

}

static int print_object(struct json_obj *item, int depth, struct printbuffer *p)
{
	int len = 7, old_offset = 0;
	struct json_obj *child = NULL;
	int numentries = 0;
	int ret = 0;

	if (p == NULL) {
		pr_err("printbuffer= NULL is not support now.\n");
		return -1;
	}

	old_offset = p->offset;
	/* Count the number of entries. */
	child = item->child;
	while (child) {
		numentries++;
		child = child->next;
	}

	/* Explicitly handle empty object case */
	if (!numentries)
		return write_buf_to_pb("{}", 2, p);

	/* Compose the output: */
	ret = write_buf_to_pb("{", 1, p);
	if (ret < 0)
		return ret;

	child = item->child;
	depth++;
	while (child)
	{
		print_string_ptr(child->string, p);

		/* print ":" */
		ret = write_buf_to_pb(":", 1, p);
		if (ret < 0)
			return ret;

		ret = print_value(child, depth, p);
		if (ret < 0)
			return ret;

		len = child->next ? 1 : 0;
		if (len) {
			ret = write_buf_to_pb(",", 1, p);
			if (ret < 0)
				return ret;
		}

		child = child->next;
	}

	ret = write_buf_to_pb("}", 1, p);
	if (ret < 0)
		return ret;

	return p->offset - old_offset;
}

static int print_string_ptr(const char *str, struct printbuffer *p)
{
	const char *ptr;
	char *ptr2,*out;
	int len = 0,flag = 0;
	unsigned char token;
	int ret;

	if (p == NULL) {
		pr_err("printbuffer== NULL is not supported\n");
		return -1;
	}

	if (!str) {
		return write_buf_to_pb("\"\"", 2, p);
	}

	for (ptr = str; *ptr; ptr++)
		flag |= ((*ptr > 0 && *ptr < 32)
				||(*ptr=='\"') || (*ptr=='\\')) ? 1 : 0;

	/* no special char */
	if (!flag) {
		len = ptr - str;
		out=ensure(p, len + 3);
		if (!out)
			return -1;
		ret = snprintf(out, len + 3, "%c%s%c", '\"', str, '\"');
		p->offset += (len + 2);
		return (len + 2);
	}

	/* has special char */
	ptr = str;
	while ((token = *ptr) && ++len) {
		if (strchr("\"\\\b\f\n\r\t", token))
			len++;
		else if (token < 32)
			len += 5;
		ptr++;
	}

	out = ensure(p, len + 3);
	if (!out)
		return -1;
	ptr2 = out;
	ptr = str;
	*ptr2++ = '\"';
	while (*ptr)
	{
		if ((unsigned char)*ptr > 31 && *ptr != '\"' && *ptr != '\\')
			*ptr2++ = *ptr++;
		else {
			*ptr2++ = '\\';
			switch (token = *ptr++)
			{
			case '\\':
				*ptr2++ = '\\';
				break;
			case '\"':
				*ptr2++ = '\"';
				break;
			case '\b':
				*ptr2++ = 'b';
				break;
			case '\f':
				*ptr2++ = 'f';
				break;
			case '\n':
				*ptr2++ = 'n';
				break;
			case '\r':
				*ptr2++ = 'r';
				break;
			case '\t':
				*ptr2++ = 't';
				break;
			default:
				sprintf(ptr2,"u%04x",token);
				ptr2 += 5;
				break;	/* escape and print */
			}
		}
	}
	*ptr2++ = '\"';
	*ptr2++ = 0;
	p->offset += (len + 2);
	return (len + 2);
}

static int print_string(struct json_obj *item, struct printbuffer *p)
{
	return print_string_ptr(item->val.valuestring, p);
}

static inline int print_null(struct json_obj *item, struct printbuffer *p)
{
	return write_buf_to_pb("null", strlen("null"), p);
}

static inline int print_nr_int(struct json_obj *item, struct printbuffer *p)
{
	int len = snprintf(NULL, 0, "%d", item->val.valueint);
	char *out = ensure(p, len + 1);

	if (!out)
		return -ENOMEM;

	len = snprintf(out, len + 1, "%d", item->val.valueint);
	p->offset += len;
	return len;
}

static inline int print_nr_long(struct json_obj *item, struct printbuffer *p)
{
	int len = snprintf(NULL, 0, "%ld", item->val.valuelong);
	char *out = ensure(p, len + 1);

	if (!out)
		return -ENOMEM;

	len = snprintf(out, len + 1, "%ld", item->val.valuelong);
	p->offset += len;
	return len;
}

void json_del_object(struct json_obj *c)
{
	struct json_obj *next;
	while (c) {
		next=c->next;
		if (c->child)
			json_del_object(c->child);
		if ((c->type == JSON_STRING) && (c->val.valuestring))
			json_free(c->val.valuestring);
		if (c->string)
			json_free(c->string);
		json_free(c);

		c=next;
	}
}

static int print_value(struct json_obj *item, int depth, struct printbuffer *p)
{
	int ret = 0;

	switch (item->type) {
	case JSON_NULL:
		ret = print_null(item, p);
		break;
	case JSON_NR_INT:
		ret = print_nr_int(item, p);
		break;
	case JSON_NR_LONG:
		ret = print_nr_long(item, p);
		break;
	case JSON_STRING:
		ret = print_string(item, p);
		break;
	case JSON_OBJECT:
		ret = print_object(item, depth, p);
		break;
	}

	return ret;
}

struct sems_info {
	int len;
	int sems_id;
};
int sems_send_buf(char *buf, int len, int sems_id)
{
	struct sems_info info;
	int fd = 0;
	int ret = 0;

	info.len = len;
	info.sems_id = sems_id;

	fd = open(FILE_SEMS_NODE, O_RDONLY);
	if (fd < 0) {
		pr_err("open %s fail err=%s\n",
				FILE_SEMS_NODE, strerror(errno));
		return -1;
	}


	ret = ioctl(fd, SEMS_CRT_JSON_OBJ, (void *)(&info));
	if(ret < 0) {
		pr_err("err=%s.\n", strerror(errno));
		goto exit;
	}

	ret = ioctl(fd, SEMS_SEND_JSON, (void*)buf);
	if(ret < 0) {
		pr_err("err=%s.\n", strerror(errno));
	}

exit:
	close(fd);
	return ret;
}

int send_json(struct json_obj *object, int sems_id)
{
	struct printbuffer temp;
	struct printbuffer *p_print = &temp;
	int ret = 0;
	void *p = NULL;

	p = (char *)json_zalloc(SEMS_BUF_LEN);
	if (p == NULL)
		return -1;

	p_print->buffer = p;
	p_print->length = SEMS_BUF_LEN;
	p_print->offset = 0;
	ret = print_value(object, 0, p_print);
	if ((ret < 0) || (p_print->offset > SEMS_UEVENT_MAX_LEN)) {
		json_free(p);
		return -1;
	}
	json_del_object(object);
	return sems_send_buf(p_print->buffer, p_print->offset, sems_id);
}

int is_sems_enable(int id)
{
	int fd, ret;
	int val = id;

	fd = open(FILE_SEMS_NODE, O_RDONLY);
	if (fd < 0) {
		pr_err("open %s fail err=%s\n", FILE_SEMS_NODE, strerror(errno));
	}

	if (fd < 0)
		return -1;

	ret = ioctl(fd, SEMS_IS_DEVICE_EN, (void *)(&val));
	if(ret < 0) {
		pr_err("err=%s\n", strerror(errno));
		return -1;
	}

	close(fd);
	return val;
}
