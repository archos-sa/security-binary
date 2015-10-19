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
#define LOG_TAG "MPEG4Extractor"
#include <utils/Log.h>

#include "include/MPEG4Extractor.h"
#include "include/SampleTable.h"
#include "include/ESDS.h"

#include <arpa/inet.h>

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <media/stagefright/foundation/ABitReader.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>
#include <utils/String8.h>

namespace android {
		extern "C" void archos_restore(int id);
		extern "C" void archos_redirect(const char* from, void *to, int id);
#define PARSE_CHUNK_ID 6
extern "C" int trampoline[];

	extern "C" status_t parseChunk(MPEG4Extractor* e, off64_t *offset, int depth) {
		do {
			//
			uint32_t hdr[2];
			if (e->mDataSource->readAt(*offset, hdr, 8) < 8)
				return ERROR_IO;

			uint64_t chunk_size = ntohl(hdr[0]);
			uint32_t chunk_type = ntohl(hdr[1]);
			off64_t data_offset = *offset + 8;

			if (chunk_size == 1) {
				if (e->mDataSource->readAt(*offset + 8, &chunk_size, 8) < 8) {
					return ERROR_IO;
				}
				chunk_size = ntoh64(chunk_size);
				data_offset += 8;

				if (chunk_size < 16) {
					// The smallest valid chunk is 16 bytes long in this case.
					return ERROR_MALFORMED;
				}
			} else if (chunk_size < 8) {
				// The smallest valid chunk is 8 bytes long.
				return ERROR_MALFORMED;
			}

			off64_t chunk_data_size = *offset + chunk_size - data_offset;

			union {
				uint32_t t;
				char c[4];
			} toto;
			toto.t = chunk_type;
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%c%c%c%c\n", __FILE__, __FUNCTION__, __LINE__,
					toto.c[3], toto.c[2], toto.c[1], toto.c[0]);

			if(chunk_type == FOURCC('c', 'o', 'v', 'r')) {
				//P 0012
				__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
				if(chunk_data_size >= SIZE_MAX -1)
					return ERROR_MALFORMED;
				__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
				//16 == kSkipBytesOfDataBox
				//P 0008
				if(chunk_data_size <= 16)
					return ERROR_MALFORMED;
				__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	 		} else if(chunk_type == FOURCC('t', 'x', '3', 'g')) {
				__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
				uint32_t type;
				const void *data;
				size_t size = 0;
//!!! mLastTrack dangerous because of MTK ABI change
#if 1
				if (!e->mLastTrack->meta->findData(
							kKeyTextFormatData, &type, &data, &size)) {
					size = 0;                                                                                                   
				}

				if ((chunk_size > SIZE_MAX) || (SIZE_MAX - chunk_size <= size))
					return ERROR_MALFORMED;
#endif
			}
		} while(0);

			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		status_t (*_trampoline)(void *e, off64_t *off, int depth) = (int (*)(void*, long long int*, int))((uint32_t)trampoline|1);
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		status_t r = _trampoline(e, offset, depth);
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, r);
		return r;

#if 0
		archos_restore(6); // Must be same id as archos_redirect call in SampleTable-archos.cpp
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		status_t r = e->parseChunk(offset, depth);
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		archos_redirect(NULL, (void*)parseChunk, 6);
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%d\n", __FILE__, __FUNCTION__, __LINE__, r);
		return r;
#endif
	}

}  // namespace android
