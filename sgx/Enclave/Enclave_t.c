#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)



typedef struct ms_ecall_foo_t {
	int ms_retval;
	int ms_i;
} ms_ecall_foo_t;

typedef struct ms_ecall_amin_t {
	int ms_retval;
	int ms_i;
} ms_ecall_amin_t;

typedef struct ms_ecall_shuffle_t {
	void* ms_arr;
	int ms_size;
} ms_ecall_shuffle_t;

typedef struct ms_ecall_chAddress_t {
	int* ms_retval;
	void* ms_a;
} ms_ecall_chAddress_t;

typedef struct ms_ecall_array_access_t {
	int ms_retval;
	void* ms_array;
	int ms_index;
} ms_ecall_array_access_t;

typedef struct ms_arrayAccessAsm_t {
	int* ms_O;
	int* ms_I;
	int ms_L;
} ms_arrayAccessAsm_t;

typedef struct ms_ecall_sgx_cpuid_t {
	int* ms_cpuinfo;
	int ms_leaf;
} ms_ecall_sgx_cpuid_t;

typedef struct ms_ocall_bar_t {
	char* ms_str;
	int* ms_ret;
} ms_ocall_bar_t;


typedef struct ms_memccpy_t {
	void* ms_retval;
	void* ms_dest;
	void* ms_src;
	int ms_val;
	size_t ms_len;
} ms_memccpy_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

static sgx_status_t SGX_CDECL sgx_ecall_function_calling_convs(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_function_calling_convs();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_foo(void* pms)
{
	ms_ecall_foo_t* ms = SGX_CAST(ms_ecall_foo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_foo_t));

	ms->ms_retval = ecall_foo(ms->ms_i);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_amin(void* pms)
{
	ms_ecall_amin_t* ms = SGX_CAST(ms_ecall_amin_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_amin_t));

	ms->ms_retval = ecall_amin(ms->ms_i);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_shuffle(void* pms)
{
	ms_ecall_shuffle_t* ms = SGX_CAST(ms_ecall_shuffle_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_arr = ms->ms_arr;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_shuffle_t));

	ecall_shuffle(_tmp_arr, ms->ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_chAddress(void* pms)
{
	ms_ecall_chAddress_t* ms = SGX_CAST(ms_ecall_chAddress_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_a = ms->ms_a;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_chAddress_t));

	ms->ms_retval = ecall_chAddress(_tmp_a);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_array_access(void* pms)
{
	ms_ecall_array_access_t* ms = SGX_CAST(ms_ecall_array_access_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_array = ms->ms_array;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_array_access_t));

	ms->ms_retval = ecall_array_access(_tmp_array, ms->ms_index);


	return status;
}

static sgx_status_t SGX_CDECL sgx_arrayAccessAsm(void* pms)
{
	ms_arrayAccessAsm_t* ms = SGX_CAST(ms_arrayAccessAsm_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_O = ms->ms_O;
	int* _tmp_I = ms->ms_I;

	CHECK_REF_POINTER(pms, sizeof(ms_arrayAccessAsm_t));

	arrayAccessAsm(_tmp_O, _tmp_I, ms->ms_L);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_sgx_cpuid(void* pms)
{
	ms_ecall_sgx_cpuid_t* ms = SGX_CAST(ms_ecall_sgx_cpuid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_cpuinfo = ms->ms_cpuinfo;
	size_t _len_cpuinfo = 4 * sizeof(*_tmp_cpuinfo);
	int* _in_cpuinfo = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_sgx_cpuid_t));
	CHECK_UNIQUE_POINTER(_tmp_cpuinfo, _len_cpuinfo);

	if (_tmp_cpuinfo != NULL) {
		_in_cpuinfo = (int*)malloc(_len_cpuinfo);
		if (_in_cpuinfo == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_cpuinfo, _tmp_cpuinfo, _len_cpuinfo);
	}
	ecall_sgx_cpuid(_in_cpuinfo, ms->ms_leaf);
err:
	if (_in_cpuinfo) {
		memcpy(_tmp_cpuinfo, _in_cpuinfo, _len_cpuinfo);
		free(_in_cpuinfo);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_function_calling_convs, 0},
		{(void*)(uintptr_t)sgx_ecall_foo, 0},
		{(void*)(uintptr_t)sgx_ecall_amin, 0},
		{(void*)(uintptr_t)sgx_ecall_shuffle, 0},
		{(void*)(uintptr_t)sgx_ecall_chAddress, 0},
		{(void*)(uintptr_t)sgx_ecall_array_access, 0},
		{(void*)(uintptr_t)sgx_arrayAccessAsm, 0},
		{(void*)(uintptr_t)sgx_ecall_sgx_cpuid, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][8];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_bar(const char* str, int ret[1])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;
	size_t _len_ret = 1 * sizeof(*ret);

	ms_ocall_bar_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_bar_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;
	ocalloc_size += (ret != NULL && sgx_is_within_enclave(ret, _len_ret)) ? _len_ret : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_bar_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_bar_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (ret != NULL && sgx_is_within_enclave(ret, _len_ret)) {
		ms->ms_ret = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_ret);
		memset(ms->ms_ret, 0, _len_ret);
	} else if (ret == NULL) {
		ms->ms_ret = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (ret) memcpy((void*)ret, ms->ms_ret, _len_ret);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_tlbShootdown()
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}

sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dest = len;
	size_t _len_src = len;

	ms_memccpy_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_memccpy_t);
	void *__tmp = NULL;

	ocalloc_size += (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) ? _len_dest : 0;
	ocalloc_size += (src != NULL && sgx_is_within_enclave(src, _len_src)) ? _len_src : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_memccpy_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_memccpy_t));

	if (dest != NULL && sgx_is_within_enclave(dest, _len_dest)) {
		ms->ms_dest = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dest);
		memcpy(ms->ms_dest, dest, _len_dest);
	} else if (dest == NULL) {
		ms->ms_dest = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (src != NULL && sgx_is_within_enclave(src, _len_src)) {
		ms->ms_src = (void*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_src);
		memcpy((void*)ms->ms_src, src, _len_src);
	} else if (src == NULL) {
		ms->ms_src = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_val = val;
	ms->ms_len = len;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (dest) memcpy((void*)dest, ms->ms_dest, _len_dest);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(3, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

