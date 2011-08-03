LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_SRC_FILES += \
      src/android/smartcard/ISmartcardServiceCallback.aidl \
      src/android/smartcard/ISmartcardService.aidl

LOCAL_MODULE:= android.smartcardapi
LOCAL_MODULE_TAGS := optional

LOCAL_JAVA_LIBRARIES := android.smartcardapi \



PRODUCT_COPY_FILES += external/SmartcardService/smartcardapi/android.smartcardapi.xml:system/etc/permissions/android.smartcardapi.xml

include $(BUILD_JAVA_LIBRARY)


# put the classes.jar, with full class files instead of classes.dex inside, into the dist directory
$(call dist-for-goals, droidcore, $(full_classes_jar):android.smartcardapi.jar)
