LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS:= -Wall -O2
LOCAL_SRC_FILES:= sems_io.c
LOCAL_STATIC_LIBRARIES:=liblog
LOCAL_C_INCLUDES+=$(ANDROID_BUILD_TOP)/kernel/msm-3.18/include/misc/
LOCAL_MODULE:= libsems
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CFLAGS:= -Wall -O2
LOCAL_SRC_FILES:= test.c
LOCAL_MODULE:= testso
LOCAL_C_INCLUDES:=$(ANDROID_BUILD_TOP)/external/json-c/
LOCAL_C_INCLUDES+=$(ANDROID_BUILD_TOP)/kernel/msm-3.18/include/misc/
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES := liblog libjson
LOCAL_STATIC_LIBRARIES:=libsems
include $(BUILD_EXECUTABLE)



