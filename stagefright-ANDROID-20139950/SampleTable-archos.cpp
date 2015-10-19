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

#define LOG_TAG "SampleTable"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "include/SampleTable.h"
#include "include/SampleIterator.h"

#include <arpa/inet.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/Utils.h>
#include <dlfcn.h>
#include <sys/mman.h>
//#include <ucontext.h>

//GIMME ucontext.h

#define NGREG 18 /* Like glibc. */

typedef int greg_t;
typedef greg_t gregset_t[NGREG];

#include <asm/sigcontext.h>
typedef struct sigcontext mcontext_t;

struct ucontext {
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
 unsigned long uc_flags;
 struct ucontext *uc_link;
 stack_t uc_stack;
 struct sigcontext uc_mcontext;
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
 sigset_t uc_sigmask;
 int unused[32 - (sizeof (sigset_t) / sizeof (int))];
 unsigned long uc_regspace[128] __attribute__((__aligned__(8)));
};

//end of ucontext.h copy

static uint32_t phh_U32_AT(const uint8_t *ptr) {
    return ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
}
namespace android {

struct SampleTable::CompositionDeltaLookup {
    CompositionDeltaLookup();

    void setEntries(
            const uint32_t *deltaEntries, size_t numDeltaEntries);

    uint32_t getCompositionTimeOffset(uint32_t sampleIndex);

private:
    Mutex mLock;

    const uint32_t *mDeltaEntries;
    size_t mNumDeltaEntries;

    size_t mCurrentDeltaEntry;
    size_t mCurrentEntrySampleIndex;

    DISALLOW_EVIL_CONSTRUCTORS(CompositionDeltaLookup);
};

static uint32_t* ptrs[16];
static uint32_t originalInstructions[16][16];
extern "C" void archos_restore(int id) {
	uint32_t *fnc = ptrs[id];

	uint32_t *fnc_base = (uint32_t*)((unsigned long)fnc & ~4095UL);
	int ret = mprotect(fnc_base, 8192, PROT_READ|PROT_WRITE|PROT_EXEC);
	for(int i=0; i<16; ++i)
		ptrs[id][i] = originalInstructions[id][i];
	mprotect(fnc_base, 8192, PROT_READ|PROT_EXEC);
}

extern "C" void archos_redirect(const char* from, void *to, int id) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%s\n", __FILE__, __FUNCTION__, __LINE__, from);
	void *hdl = dlopen("libstagefright.so", RTLD_NOW|RTLD_LOCAL);

	uint32_t *fnc = NULL;
	if(from) {
		fnc = (uint32_t*)((uint32_t)dlsym(hdl, from)&~1);
	} else { 
		fnc = ptrs[id];
	}
__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fnc);
	if(!fnc) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB Couldn't redirect function %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fnc);
		return;
	}
	ptrs[id] = fnc;

	uint32_t *fnc_base = (uint32_t*)((unsigned long)fnc & ~4095UL);
	int ret = mprotect(fnc_base, 8192, PROT_READ|PROT_WRITE|PROT_EXEC);

	for(int i=0; i<16; ++i)
		originalInstructions[id][i] = fnc[i];

	for(int i=0; i<15; ++i)
		fnc[i] = 0x46c046c0; //T2 nop
	
	fnc[7] = 0x46c04778; //T2 bx pc ; noop (switch to ARM mode)
	fnc[8] = 0xe320f000; //ARM nop
	fnc[9] = 0xe320f000;
	fnc[10] = 0xe320f000;
	fnc[11] = 0xe51ff000; // ARM ldr pc, [pc, 0]
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	fnc[12] = 0x00020003; //Canari
	fnc[13] = ((uint32_t)to) | 1;
	fnc[14] = 0x00020083; //Canari
	fnc[15] = 0x000200c3; //Canari
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	mprotect(fnc_base, 8192, PROT_READ|PROT_EXEC);
}

extern "C" {
	int trampoline[] = {
		0xaabbccdd, //0. The original 4 bytes which got overriden by SIGILL
		0x46c04778, //1. Switch to ARM mode (bx pc; nop)
		0xe320f000, //2. ARM nop
		0xe51ff000, //3. ARM ldr pc, [pc, 0]
		0x00020003, //4. Canari
		0xaabbccdd, //5. The emplacement of original function (pos = 4)
		0x00020003, //6. Canari
	};
};

extern "C" status_t parseChunk(void* e, off64_t* offset, int depth);
extern "C" void sigill_fnc(int signal, siginfo_t *si, ucontext *arg) {
	int fncId = -1;
	uint32_t *siaddr = (uint32_t*)((uint32_t)si->si_addr&~1);
	for(int i=0; i<(sizeof(ptrs)/sizeof(ptrs[0])); ++i) {
		uint32_t *ptrs2 = (uint32_t*)((uint32_t)ptrs[i]&~1);
		if( ptrs2 == siaddr) {
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, ptrs[i]);
			fncId = i;
		}
	}
	__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fncId);
	__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, si->si_addr);
	if(fncId == -1) {
		exit(1);
	}

	uint32_t* _a = (uint32_t*)arg;
	for(int i=0; i<32; ++i) {
		if( (_a[i]|1) == ((uint32_t)siaddr|1) )
			__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:r%d:%p\n", __FILE__, __FUNCTION__, __LINE__, i, _a[i]);
	}

	for(int i=-15; i<16; ++i)
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:d%d:%p\n", __FILE__, __FUNCTION__, __LINE__, i, siaddr[i]);

	// 23?!?
	//Change PC
	//_a[23] = ((uint32_t)trampoline)|1; // We start in thumb mode

	//Jump to our parseChunk
	_a[23] = ((uint32_t)parseChunk)|1; // We start in thumb mode

	__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:r%d:%p\n", __FILE__, __FUNCTION__, __LINE__, -1, _a[23]);
	
	//exit(1);
}

extern "C" void archos_redirect2(const char* from, void *to, int id) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%s\n", __FILE__, __FUNCTION__, __LINE__, from);
	void *hdl = dlopen("libstagefright.so", RTLD_NOW|RTLD_LOCAL);

	uint32_t *fnc = NULL;
	if(from) {
		fnc = (uint32_t*)((uint32_t)dlsym(hdl, from)&~1);
	} else { 
		fnc = ptrs[id];
	}
__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fnc);
	if(!fnc) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB Couldn't redirect function %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fnc);
		return;
	}
	ptrs[id] = fnc;

	uint32_t *fnc_base = (uint32_t*)((unsigned long)fnc & ~4095UL);
	int ret = mprotect(fnc_base, 8192, PROT_READ|PROT_WRITE|PROT_EXEC);

	for(int i=0; i<16; ++i)
		originalInstructions[id][i] = fnc[i];


	//Store first 4 bytes
	trampoline[0] = fnc[0];

	//Make first instruction of the function segfault
	fnc[0] = 0xde0dee8d; //CDP p14, #8, C13, C13, C13 == sigill

	//trampoline will execute first 4 bytes, trampoline will jump after those 4 bytes
	trampoline[5] = ((uint32_t)fnc+4) | 1;

	mprotect(fnc_base, 8192, PROT_READ|PROT_EXEC);

	//Make trampoline executable
	mprotect((void*)(((uint32_t)trampoline)&~4093), 8192, PROT_READ|PROT_WRITE|PROT_EXEC);
}

extern "C" {
	//ESDS-archos.cpp
	extern status_t parseESDescriptor(void* e, size_t offset, size_t size);
	//MPEG4Extractor-archos.cpp
	extern status_t parseChunk(void* e, off64_t* offset, int depth);

	static status_t setSampleToChunkParams(SampleTable* s, off64_t o, size_t d) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setSampleToChunkParams2(o, d);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}

	static status_t setTimeToSampleParams(SampleTable* s, off64_t o, size_t d) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setTimeToSampleParams2(o, d);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}

	static status_t setTimeToSampleParamsMTK(SampleTable* s, off64_t o, size_t d, uint32_t v) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setTimeToSampleParamsMTK(o, d, v);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}

	static status_t setCompositionTimeToSampleParams(SampleTable* s, off64_t o, size_t d) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setCompositionTimeToSampleParams2(o, d);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}

	static status_t setCompositionTimeToSampleParamsMTK(SampleTable* s, off64_t o, size_t d, uint32_t v) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setCompositionTimeToSampleParamsMTK(o, d, v);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}

	static status_t setSyncSampleParams(SampleTable* s, off64_t o, size_t d) {
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d %p %lld %d\n", __FILE__, __FUNCTION__, __LINE__, s, o, d);
		status_t r = s->setSyncSampleParams2(o, d);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
		return r;
	}
};


__attribute__((constructor)) static void init() {
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = (void (*)(int, siginfo*, void*))sigill_fnc;
	sa.sa_flags   = SA_SIGINFO;
	sigaction(SIGILL, &sa, NULL);

	archos_redirect("_ZN7android11SampleTable22setSampleToChunkParamsExj", (void*)setSampleToChunkParams, 0);
	archos_redirect("_ZN7android11SampleTable21setTimeToSampleParamsExj", (void*)setTimeToSampleParams, 1);
	archos_redirect("_ZN7android11SampleTable21setTimeToSampleParamsExjj", (void*)setTimeToSampleParamsMTK, 2);
	archos_redirect("_ZN7android11SampleTable32setCompositionTimeToSampleParamsExj", (void*)setCompositionTimeToSampleParams, 3);
	archos_redirect("_ZN7android11SampleTable19setSyncSampleParamsExj", (void*)setSyncSampleParams, 4);

	archos_redirect("_ZN7android4ESDS17parseESDescriptorEjj", (void*)parseESDescriptor, 5);

	//archos_redirect("_ZN7android14MPEG4Extractor10parseChunkEPxi", (void*)parseChunk, 6);
	archos_redirect2("_ZN7android14MPEG4Extractor10parseChunkEPxi", (void*)parseChunk, 6);

	archos_redirect("_ZN7android11SampleTable32setCompositionTimeToSampleParamsExjj", (void*)setCompositionTimeToSampleParams, 7);

#if 0
	void *hdl_archos = dlopen("libstagefright_archos.so", RTLD_NOW|RTLD_LOCAL);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, hdl_archos);
	uint32_t *fnc_new = (uint32_t*)dlsym(hdl_archos, "_ZN7android11SampleTable23setSampleToChunkParams2Exj");
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d:%p\n", __FILE__, __FUNCTION__, __LINE__, fnc_new);
#endif
}

status_t SampleTable::setSampleToChunkParams2(
        off64_t data_offset, size_t data_size) {
    if (mSampleToChunkOffset >= 0) {
        return ERROR_MALFORMED;
    }

    mSampleToChunkOffset = data_offset;

    if (data_size < 8) {
        return ERROR_MALFORMED;
    }

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header)) < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }

    mNumSampleToChunkOffsets = U32_AT(&header[4]);

    if (data_size < 8 + mNumSampleToChunkOffsets * 12) {
        return ERROR_MALFORMED;
    }

	if (SIZE_MAX / sizeof(SampleToChunkEntry) <= mNumSampleToChunkOffsets)                                             
		return ERROR_OUT_OF_RANGE;                                                                                     

    mSampleToChunkEntries =
        new SampleToChunkEntry[mNumSampleToChunkOffsets];

    for (uint32_t i = 0; i < mNumSampleToChunkOffsets; ++i) {
        uint8_t buffer[12];
        if (mDataSource->readAt(
                    mSampleToChunkOffset + 8 + i * 12, buffer, sizeof(buffer))
                != (ssize_t)sizeof(buffer)) {
            return ERROR_IO;
        }

        CHECK(U32_AT(buffer) >= 1);  // chunk index is 1 based in the spec.

        // We want the chunk index to be 0-based.
        mSampleToChunkEntries[i].startChunk = U32_AT(buffer) - 1;
        mSampleToChunkEntries[i].samplesPerChunk = U32_AT(&buffer[4]);
        mSampleToChunkEntries[i].chunkDesc = U32_AT(&buffer[8]);
    }

    return OK;
}

status_t SampleTable::setTimeToSampleParams2(
        off64_t data_offset, size_t data_size) {
    if (mTimeToSample != NULL || data_size < 8) {
        return ERROR_MALFORMED;
    }

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header)) < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }

    mTimeToSampleCount = U32_AT(&header[4]);
    uint64_t allocSize = mTimeToSampleCount * 2 * (uint64_t)sizeof(uint32_t);
    if (allocSize > SIZE_MAX) {
        return ERROR_OUT_OF_RANGE;
    }
    mTimeToSample = new uint32_t[mTimeToSampleCount * 2];

    size_t size = sizeof(uint32_t) * mTimeToSampleCount * 2;
    if (mDataSource->readAt(
                data_offset + 8, mTimeToSample, size) < (ssize_t)size) {
        return ERROR_IO;
    }

    for (uint32_t i = 0; i < mTimeToSampleCount * 2; ++i) {
        mTimeToSample[i] = ntohl(mTimeToSample[i]);
    }

    return OK;
}

status_t SampleTable::setTimeToSampleParamsMTK(
        off64_t data_offset, size_t data_size, uint32_t timescaleFactor) {
    if (mTimeToSample != NULL || data_size < 8) {
        return ERROR_MALFORMED;
    }

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header)) < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }

    mTimeToSampleCount = U32_AT(&header[4]);
    uint64_t allocSize = mTimeToSampleCount * 2 * (uint64_t)sizeof(uint32_t);
    if (allocSize > SIZE_MAX) {
        return ERROR_OUT_OF_RANGE;
    }
    mTimeToSample = new uint32_t[mTimeToSampleCount * 2];

    size_t size = sizeof(uint32_t) * mTimeToSampleCount * 2;
    if (mDataSource->readAt(
                data_offset + 8, mTimeToSample, size) < (ssize_t)size) {
        return ERROR_IO;
    }

    for (uint32_t i = 0; i < mTimeToSampleCount * 2; ++i) {
        mTimeToSample[i] = ntohl(mTimeToSample[i]);
		//M:{
		if (i%2 == 1 && timescaleFactor != 0) {
			mTimeToSample[i] /= timescaleFactor;
		}
		//}:M
    }

    return OK;
}

status_t SampleTable::setCompositionTimeToSampleParams2(
        off64_t data_offset, size_t data_size) {
    ALOGI("There are reordered frames present.");
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    if (mCompositionTimeDeltaEntries != NULL || data_size < 8) {
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header))
            < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    size_t numEntries = U32_AT(&header[4]);

    if (data_size != (numEntries + 1) * 8) {
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mNumCompositionTimeDeltaEntries = numEntries;
    uint64_t allocSize = numEntries * 2 * (uint64_t)sizeof(uint32_t);
    if (allocSize > SIZE_MAX) {
        return ERROR_OUT_OF_RANGE;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mCompositionTimeDeltaEntries = new uint32_t[2 * numEntries];

		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
    if (mDataSource->readAt(
                data_offset + 8, mCompositionTimeDeltaEntries, numEntries * 8)
            < (ssize_t)numEntries * 8) {
        delete[] mCompositionTimeDeltaEntries;
        mCompositionTimeDeltaEntries = NULL;

        return ERROR_IO;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    for (size_t i = 0; i < 2 * numEntries; ++i) {
        mCompositionTimeDeltaEntries[i] = ntohl(mCompositionTimeDeltaEntries[i]);
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mCompositionDeltaLookup->setEntries(
            mCompositionTimeDeltaEntries, mNumCompositionTimeDeltaEntries);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    return OK;
}

status_t SampleTable::setCompositionTimeToSampleParamsMTK(
        off64_t data_offset, size_t data_size, uint32_t timescaleFactor) {
    ALOGI("There are reordered frames present.");
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    if (mCompositionTimeDeltaEntries != NULL || data_size < 8) {
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header))
            < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    size_t numEntries = U32_AT(&header[4]);

    if (data_size != (numEntries + 1) * 8) {
        return ERROR_MALFORMED;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mNumCompositionTimeDeltaEntries = numEntries;
    uint64_t allocSize = numEntries * 2 * (uint64_t)sizeof(uint32_t);
    if (allocSize > SIZE_MAX) {
        return ERROR_OUT_OF_RANGE;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mCompositionTimeDeltaEntries = new uint32_t[2 * numEntries];

		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
    if (mDataSource->readAt(
                data_offset + 8, mCompositionTimeDeltaEntries, numEntries * 8)
            < (ssize_t)numEntries * 8) {
        delete[] mCompositionTimeDeltaEntries;
        mCompositionTimeDeltaEntries = NULL;

        return ERROR_IO;
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    for (size_t i = 0; i < 2 * numEntries; ++i) {
		mCompositionTimeDeltaEntries[i] = ntohl(mCompositionTimeDeltaEntries[i]);
		if (i%2 == 1 && timescaleFactor != 0) {                                                                                
			mCompositionTimeDeltaEntries[i] /= timescaleFactor;                                                                
		}
    }
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    mCompositionDeltaLookup->setEntries(
            mCompositionTimeDeltaEntries, mNumCompositionTimeDeltaEntries);
		__android_log_print(ANDROID_LOG_ERROR, "AAAA", "BBB %s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

    return OK;
}

status_t SampleTable::setSyncSampleParams2(off64_t data_offset, size_t data_size) {
    if (mSyncSampleOffset >= 0 || data_size < 8) {
        return ERROR_MALFORMED;
    }

    mSyncSampleOffset = data_offset;

    uint8_t header[8];
    if (mDataSource->readAt(
                data_offset, header, sizeof(header)) < (ssize_t)sizeof(header)) {
        return ERROR_IO;
    }

    if (U32_AT(header) != 0) {
        // Expected version = 0, flags = 0.
        return ERROR_MALFORMED;
    }

    mNumSyncSamples = U32_AT(&header[4]);

    if (mNumSyncSamples < 2) {
        ALOGV("Table of sync samples is empty or has only a single entry!");
    }

    uint64_t allocSize = mNumSyncSamples * (uint64_t)sizeof(uint32_t);
    if (allocSize > SIZE_MAX) {
        return ERROR_OUT_OF_RANGE;
    }

    mSyncSamples = new uint32_t[mNumSyncSamples];
    size_t size = mNumSyncSamples * sizeof(uint32_t);
    if (mDataSource->readAt(mSyncSampleOffset + 8, mSyncSamples, size)
            != (ssize_t)size) {
        return ERROR_IO;
    }

    for (size_t i = 0; i < mNumSyncSamples; ++i) {
        mSyncSamples[i] = ntohl(mSyncSamples[i]) - 1;
    }

    return OK;
}


}  // namespace android

