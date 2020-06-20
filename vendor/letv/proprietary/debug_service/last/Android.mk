LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CFLAGS:= -Wall -O2
LOCAL_C_INCLUDES:=$(ANDROID_BUILD_TOP)/kernel/msm-3.18/kernel/printk
LOCAL_SRC_FILES:= lastsvc.c
LOCAL_MODULE:= lastsvc
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_STATIC_LIBRARIES:=libinit liblog
LOCAL_SHARED_LIBRARIES := libcutils libselinux
include $(BUILD_EXECUTABLE)

