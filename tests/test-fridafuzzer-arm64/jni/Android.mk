LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE:= fridafuzzer_test
LOCAL_SRC_FILES := test.c

LOCAL_CFLAGS += -g
#LOCAL_LDFLAGS += -pie -fPIE
# Don't strip debug builds
# ifeq ($(NDK_DEBUG),1)
#ifeq ($(APP_OPTIM),debug)
#       cmd-strip := 
#endif
include $(BUILD_EXECUTABLE)

