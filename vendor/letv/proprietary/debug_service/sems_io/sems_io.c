#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define LOG_TAG "sems"
#include <cutils/log.h>

#include "sems_io.h"

int get_sems_dev_name(int dev_id, char *name)
{
	int fd, ret;
	int *val = (int *)name;

	fd = open(FILE_SEMS_NODE, O_RDONLY);
	if (fd < 0) {
		ALOGE("open %s fail err=%s\n", FILE_SEMS_NODE, strerror(errno));
		return -1;
	}

	*val = dev_id;
	ret = ioctl(fd, SEMS_GET_DEVICE_NAME, name);
	if (ret == -1)
		ALOGE("sems device is not enabled.\n");
	else if(ret < 0)
		ALOGE("err=%s\n", strerror(errno));

	ALOGE("ret=%d\n", ret);
	close(fd);
	return ret;
}

long system_current_time_millis(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    long when = now.tv_sec * 1000LL + now.tv_usec / 1000;
    return when;
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
		ALOGE("open %s fail err=%s\n",
				FILE_SEMS_NODE, strerror(errno));
		return -1;
	}


	ret = ioctl(fd, SEMS_CRT_JSON_OBJ, (void *)(&info));
	if(ret < 0) {
		ALOGE("err=%s.\n", strerror(errno));
		goto exit;
	}

	ret = ioctl(fd, SEMS_SEND_JSON, (void*)buf);
	if(ret < 0) {
		ALOGE("err=%s.\n", strerror(errno));
	}

exit:
	close(fd);
	return ret;
}
