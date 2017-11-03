#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_bar, (const char* str, int ret[1]));
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_tlbShootdown, ());
SGX_DLLIMPORT void* SGX_UBRIDGE(SGX_CDECL, memccpy, (void* dest, const void* src, int val, size_t len));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));

sgx_status_t ecall_function_calling_convs(sgx_enclave_id_t eid);
sgx_status_t ecall_foo(sgx_enclave_id_t eid, int* retval, int i);
sgx_status_t ecall_amin(sgx_enclave_id_t eid, int* retval, int i);
sgx_status_t ecall_shuffle(sgx_enclave_id_t eid, void* arr, int size);
sgx_status_t ecall_chAddress(sgx_enclave_id_t eid, int** retval, void* a);
sgx_status_t ecall_sgx_cpuid(sgx_enclave_id_t eid, int cpuinfo[4], int leaf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
