LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_SRC_FILES += \
      openmobileapi/src/org/simalliance/openmobileapi/service/ISmartcardServiceCallback.aidl \
      openmobileapi/src/org/simalliance/openmobileapi/service/ISmartcardService.aidl

LOCAL_AIDL_INCLUDES := external/SmartcardService/openmobileapi/src/org/simalliance/openmobileapi/service

LOCAL_PACKAGE_NAME := SmartcardService
LOCAL_CERTIFICATE := platform

LOCAL_JAVA_LIBRARIES := core framework

LOCAL_PROGUARD_FLAGS := -include $(LOCAL_PATH)/proguard.flags

include $(BUILD_PACKAGE)

include $(call all-makefiles-under,$(LOCAL_PATH))
