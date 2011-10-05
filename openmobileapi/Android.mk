LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_SRC_FILES += \
      src/android/smartcard/ISmartcardServiceCallback.aidl \
      src/android/smartcard/ISmartcardService.aidl

LOCAL_MODULE:= org.simalliance.openmobileapi
LOCAL_MODULE_TAGS := optional

PRODUCT_COPY_FILES += external/SmartcardService/openmobileapi/org.simalliance.openmobileapi.xml:system/etc/permissions/org.simalliance.openmobileapi.xml

include $(BUILD_JAVA_LIBRARY)


# put the classes.jar, with full class files instead of classes.dex inside, into the dist directory
$(call dist-for-goals, droidcore, $(full_classes_jar):org.simalliance.openmobileapi.jar)
