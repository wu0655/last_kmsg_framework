#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define LOG_TAG "semsapp"
#include <cutils/log.h>

#include "cJSON.h"

int exception_report_main(int dev_id)
{
	struct json_obj *root, *private;
	char *mod_name = get_sems_dev_name(dev_id);

	/* this is MUST */
	if (!is_sems_enable(dev_id))
		return -1;
	root = json_crt_object();
	private = json_crt_object();
	if ((root == NULL) || (private == NULL) || (mod_name == NULL))
		return -1;
	json_add_time(root, system_current_time_millis());
	json_add_string(root, "issue_category", mod_name);
	json_add_nr_int(root, "type", SEMS_DEVICE_TYPE);
	json_add_child(root, "private_data", private);
	/* user add info as needed. */

	/* this is MUST */
	return send_json(root, dev_id);
}

int main(int argc, char **argv)
{
	int dev_id = -1;
	int i;

	for(i=0; i<argc; i++) {
		ALOGI("argv[%d]=%s.\n", i, argv[i]);
	}

	if (argc > 1)
		dev_id = atoi(argv[1]);

	if ((dev_id >= SEMS_ID_MAX) || (dev_id < SEMS_ID_MIN)) {
		ALOGE("intput arg wrong dev_id is out of range\n");
		return -1;
	}

	return exception_report_main(dev_id);
}
