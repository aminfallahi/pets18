#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include <string.h>
#include <sgx_cpuid.h>

#include "sgx_trts.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* bar*/

#include <math.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int bar1(const char *fmt, ...) {
    int ret[1];
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_bar(buf, ret);
    return ret[0];
}

/* ecall_foo:
 *   Uses malloc/free to allocate/free trusted memory.
 */
int ecall_foo(int i) {
    void *ptr = malloc(100);
    assert(ptr != NULL);
    memset(ptr, 0x0, 100);
    free(ptr);

    int ret = bar1("calling ocall_bar with: %d\n", 23);
    bar1("ocall_bar returns: %d\n", ret);

    return i + 1;
}

int ecall_amin(int i) {
    //ocall_tlbShootdown();
    void *ptr = malloc(100);
    assert(ptr != NULL);
    memset(ptr, 0x0, 100);
    free(ptr);

    int a[1000];
    for (i = 0; i < 1000; i++)
        a[i] = i;
    for (i = 0; i < 1000; i += 2) {
        ocall_tlbShootdown();
        int c = a[i];
        a[i] = a[i + 1];
        a[i + 1] = c;
    }
    while (i > 0) i /= 2;

    return i + 1;
}

void ecall_shuffle(void* arr, int size) {
    //ocall_tlbShootdown();
    int *tmp = (int*) arr;
    int *p = (int*) malloc(size * size * sizeof (int));
    int i, j, k, c;
    for (i = 0; i < size; i++) {
        sgx_read_rand((unsigned char *) &c, sizeof (int));
        p[i] = c % size;
    }
    //Bubblesort
    /*
            for (i=0; i<size-1; i++)
                    for (j=0; j<size-i-1; j++)
                            if (p[j]<p[j+1]){
                                    c=p[j];
                                    p[j]=p[j+1];
                                    p[j+1]=c;
                                    c=tmp[j];
                                    tmp[j]=tmp[j+1];
                                    tmp[j+1]=c;
                            }*/
    //Bitonic Sort
    /*for (k = 2; k <= size; k = 2 * k) {
        for (j = k >> 1; j > 0; j = j >> 1) {
            for (i = 0; i < size; i++) {
                int ij = i^j;
                if ((ij) > i) {
                    if ((i & k) == 0 && p[i] > p[ij]) {
                        c = p[i];
                        p[i] = p[ij];
                        p[ij] = c;
                        c = tmp[i];
                        tmp[i] = tmp[ij];
                        tmp[ij] = c;
                    }
                    if ((i & k) != 0 && p[i] < p[ij]) {
                        c = p[i];
                        p[i] = p[ij];
                        p[ij] = c;
                        c = tmp[i];
                        tmp[i] = tmp[ij];
                        tmp[ij] = c;
                    }
                }
            }
        }
    }*/
    //Batcher's Odd-Even Mergesort
    int t = ceil(log2(size));
    int P = pow(2, t - 1);

    while (P > 0) {
        int q = pow(2, t - 1);
        int r = 0;
        int d = P;

        while (d > 0) {
            for (i = 0; i < size - d; ++i) {
                if ((i & P) == r) {
                    if (p[i] < p[i + d]) {
                        c = p[i];
                        p[i] = p[i + d];
                        p[i + d] = c;
                        c = tmp[i];
                        tmp[i] = tmp[i + d];
                        tmp[i + d] = c;
                    }
                }
            }

            d = q - P;
            q /= 2;
            r = P;
        }
        P /= 2;
    }
    //End Sorting
    arr = (void*) tmp;

}

int* ecall_chAddress(void *a) {
    int tmp = *((int*) a);
    a = &tmp;
    return (int*) a;
}

/* ecall_sgx_cpuid:
 *   Uses sgx_cpuid to get CPU features and types.
 */
void ecall_sgx_cpuid(int cpuinfo[4], int leaf) {
    sgx_status_t ret = sgx_cpuid(cpuinfo, leaf);
    if (ret != SGX_SUCCESS)
        abort();
}

int ecall_array_access(void *arr, int index) {
    int *_arr = (int*) arr;
    int *out = (int*) malloc(sizeof (int)*8);
    int i, j;
    for (i = index, j = 0; j < 8; j++, i += 8)
        out[j] = i;
    arrayAccessAsm(out, _arr, 128);
    return /*out[index/8+1]*/1;
}

void arrayAccessAsm(int* O, int *I, int L) {
    //__m128i _mm_cmpeq_epi32 ( __m128i a, __m128i b)
    //	__m128i sse_pi = _mm_load_si128((__m128i*)O);
    __asm__(
            "mov $0,%rdx\n\t"
            "vpcmpeqd %ymm0,%ymm0,%ymm0\n\t"
            "vmovups  (%rdi,%rdx,4),%ymm1 ;\n\t"
            //            "VPGATHERDD %ymm0,(%rsi,%ymm1,4),%ymm2\n\t"
            //            "vmovups %ymm1,(%rdi,%rdx,4)\n\t"
            //            "vzeroall\n\t"
            );
}

int ecall_intAccess(void * in, int index, int size) {
    int *arr = (int*) in;
    int r, i;
    for (i = 0; i < 8; i++) {
        sgx_read_rand((unsigned char *) &r, sizeof (int));
        bar1("%d\n",&(*(arr + r % size)));
    }
    return *(arr + index);
}


int intAccess(int *arr, int index, int size)
{
    int r, i;
    for (i = 0; i < 8; i++) {
        sgx_read_rand((unsigned char *) &r, sizeof (int));
        bar1("%d\n",&(*(arr + r % size)));
    }
    return *(arr + index);

}

