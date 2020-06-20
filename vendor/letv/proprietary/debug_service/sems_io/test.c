#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define LOG_TAG "semsapp"
#include <cutils/log.h>

#include "json.h"
#include "sems_io.h"

int json_main(int dev_id)
{
	struct json_obj *root, *private, *obj;
	char mod_name[SEMS_DEV_NAME_MAX_LEN];
	int ret;
	char *out;

	/* don't change anything. just copy it */
	ret = get_sems_dev_name(dev_id, mod_name);
	if (ret < 0)
		return ret;

	root = json_object_new_object();
	private = json_object_new_object();
	if ((root == NULL) || (private == NULL))
		return -1;
	obj = json_object_new_int64(system_current_time_millis());
	json_object_object_add(root, "exception_time", obj);
	obj = json_object_new_string(mod_name);
	json_object_object_add(root, "issue_category", obj);
	obj = json_object_new_int(SEMS_DEVICE_TYPE);
	json_object_object_add(root, "type", obj);
	json_object_object_add(root, "private_data", private);

	/* changed the value as needed, don't change name. */
	obj = json_object_new_string("aaa");
	json_object_object_add(root, "issue_type", obj);
	obj = json_object_new_string("bbb");
	json_object_object_add(root, "issue_arg", obj);

	/* changed the value and the name as  needed */
	obj = json_object_new_string("ccc");
	json_object_object_add(root, "reason", obj);
	obj = json_object_new_string("ddd");
	json_object_object_add(root, "mac", obj);
	obj = json_object_new_string("eee");
	json_object_object_add(root, "ssid", obj);
	obj = json_object_new_string("fff");
	json_object_object_add(root, "bssid", obj);
	obj = json_object_new_string("ggg");
	json_object_object_add(root, "ip", obj);
	obj = json_object_new_string("hhh");
	json_object_object_add(root, "gateway", obj);

	/* don't change it */
	out = json_object_to_json_string_ext(root, 0);
	sems_send_buf(out, strlen(out), dev_id);
	return 0;
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

	json_main(dev_id);
}
