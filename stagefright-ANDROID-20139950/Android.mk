LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := SampleTable-archos.cpp ESDS-archos.cpp MPEG4Extractor-archos.cpp
LOCAL_MODULE:= libstagefright_archos
LOCAL_SHARED_LIBRARIES += liblog libdl libstagefright
include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))

