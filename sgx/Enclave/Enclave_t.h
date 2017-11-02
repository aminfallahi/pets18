#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "user_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void ecall_function_calling_convs();
int ecall_foo(int i);
int ecall_amin(int i);
void ecall_sgx_cpuid(int cpuinfo[4], int leaf);

sgx_status_t SGX_CDECL ocall_bar(const char* str, int ret[1]);
sgx_status_t SGX_CDECL memccpy(void** retval, void* dest, const void* src, int val, size_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
