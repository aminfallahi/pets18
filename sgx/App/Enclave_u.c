#include "Enclave_u.h"
#include <errno.h>


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

typedef struct ms_ecall_intAccess_t {
	int ms_retval;
	void* ms_in;
	int ms_index;
	int ms_size;
} ms_ecall_intAccess_t;

typedef struct ms_ecall_mergeSort_t {
	void* ms__arr;
	int ms_l;
	int ms_r;
} ms_ecall_mergeSort_t;

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

static sgx_status_t SGX_CDECL Enclave_ocall_bar(void* pms)
{
	ms_ocall_bar_t* ms = SGX_CAST(ms_ocall_bar_t*, pms);
	ocall_bar((const char*)ms->ms_str, ms->ms_ret);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_tlbShootdown(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_tlbShootdown();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_memccpy(void* pms)
{
	ms_memccpy_t* ms = SGX_CAST(ms_memccpy_t*, pms);
	ms->ms_retval = memccpy(ms->ms_dest, (const void*)ms->ms_src, ms->ms_val, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_Enclave = {
	4,
	{
		(void*)Enclave_ocall_bar,
		(void*)Enclave_ocall_tlbShootdown,
		(void*)Enclave_memccpy,
		(void*)Enclave_sgx_oc_cpuidex,
	}
};
sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_foo(sgx_enclave_id_t eid, int* retval, int i)
{
	sgx_status_t status;
	ms_ecall_foo_t ms;
	ms.ms_i = i;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_amin(sgx_enclave_id_t eid, int* retval, int i)
{
	sgx_status_t status;
	ms_ecall_amin_t ms;
	ms.ms_i = i;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_shuffle(sgx_enclave_id_t eid, void* arr, int size)
{
	sgx_status_t status;
	ms_ecall_shuffle_t ms;
	ms.ms_arr = arr;
	ms.ms_size = size;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_chAddress(sgx_enclave_id_t eid, int** retval, void* a)
{
	sgx_status_t status;
	ms_ecall_chAddress_t ms;
	ms.ms_a = a;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_array_access(sgx_enclave_id_t eid, int* retval, void* array, int index)
{
	sgx_status_t status;
	ms_ecall_array_access_t ms;
	ms.ms_array = array;
	ms.ms_index = index;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t arrayAccessAsm(sgx_enclave_id_t eid, int* O, int* I, int L)
{
	sgx_status_t status;
	ms_arrayAccessAsm_t ms;
	ms.ms_O = O;
	ms.ms_I = I;
	ms.ms_L = L;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_intAccess(sgx_enclave_id_t eid, int* retval, void* in, int index, int size)
{
	sgx_status_t status;
	ms_ecall_intAccess_t ms;
	ms.ms_in = in;
	ms.ms_index = index;
	ms.ms_size = size;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_mergeSort(sgx_enclave_id_t eid, void* _arr, int l, int r)
{
	sgx_status_t status;
	ms_ecall_mergeSort_t ms;
	ms.ms__arr = _arr;
	ms.ms_l = l;
	ms.ms_r = r;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf)
{
	sgx_status_t status;
	ms_ecall_sgx_cpuid_t ms;
	ms.ms_cpuinfo = (int*)cpuinfo;
	ms.ms_leaf = leaf;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

