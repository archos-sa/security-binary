/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "ESDS"
#include <utils/Log.h>

#include "include/ESDS.h"

#include <string.h>

namespace android {

extern "C" {
	status_t parseESDescriptor(ESDS* e, size_t offset, size_t size) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %d %d\n", __FILE__, __FUNCTION__, __LINE__, e, offset, size);
		status_t r = e->parseESDescriptor2(offset, size);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%d\n", __FILE__, __FUNCTION__, __LINE__, r);
		return r;
	}
};

status_t ESDS::parseESDescriptor2(size_t offset, size_t size) {
    if (size < 3) {
        return ERROR_MALFORMED;
    }

    offset += 2;  // skip ES_ID
    size -= 2;

    unsigned streamDependenceFlag = mData[offset] & 0x80;
    unsigned URL_Flag = mData[offset] & 0x40;
    unsigned OCRstreamFlag = mData[offset] & 0x20;

    ++offset;
    --size;

    if (streamDependenceFlag) {
		if (size < 2)
			return ERROR_MALFORMED;
        offset += 2;
        size -= 2;
    }

    if (URL_Flag) {
        if (offset >= size) {
            return ERROR_MALFORMED;
        }
        unsigned URLlength = mData[offset];
		if (URLlength >= size)
			return ERROR_MALFORMED;
        offset += URLlength + 1;
        size -= URLlength + 1;
    }

    if (OCRstreamFlag) {
		if (size < 2)
			return ERROR_MALFORMED;
        offset += 2;
        size -= 2;

        if ((offset >= size || mData[offset] != kTag_DecoderConfigDescriptor)
                && offset - 2 < size
                && mData[offset - 2] == kTag_DecoderConfigDescriptor) {
            // Content found "in the wild" had OCRstreamFlag set but was
            // missing OCR_ES_Id, the decoder config descriptor immediately
            // followed instead.
            offset -= 2;
            size += 2;

            ALOGW("Found malformed 'esds' atom, ignoring missing OCR_ES_Id.");
        }
    }

    if (offset >= size) {
        return ERROR_MALFORMED;
    }

    uint8_t tag;
    size_t sub_offset, sub_size;
    status_t err = skipDescriptorHeader(
            offset, size, &tag, &sub_offset, &sub_size);

    if (err != OK) {
        return err;
    }

    if (tag != kTag_DecoderConfigDescriptor) {
        return ERROR_MALFORMED;
    }

    err = parseDecoderConfigDescriptor(sub_offset, sub_size);

    return err;
}

}  // namespace android

