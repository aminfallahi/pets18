#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include <string.h>
#include <sgx_cpuid.h>

#include "sgx_trts.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* bar*/



/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int bar1(const char *fmt, ...)
{
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
int ecall_foo(int i)
{
    void *ptr = malloc(100);
    assert(ptr != NULL);
    memset(ptr, 0x0, 100);
    free(ptr);

int ret = bar1("calling ocall_bar with: %d\n", 23);
bar1("ocall_bar returns: %d\n", ret);

    return i+1;
}

int ecall_amin(int i)
{
    void *ptr = malloc(100);
    assert(ptr != NULL);
    memset(ptr, 0x0, 100);
    free(ptr);

int ret = bar1("calling ocall_bar with: %d\n", 23);
bar1("ocall_bar returns: %d\n", ret);

    return i+1;
}

void ecall_shuffle(void* arr, int size)
{
	ocall_tlbShootdown();
	int *tmp=(int*)arr;
	int *p=(int*)malloc(size*sizeof(int));
	int i,j,k,c;
	for (i=0; i<size; i++){
		sgx_read_rand((unsigned char *) &c, sizeof(int));
		p[i]=c%size;
	}

/*	for (i=0; i<size-1; i++)
		for (j=0; j<size-i-1; j++)
			if (p[j]<p[j+1]){
				c=p[j];
				p[j]=p[j+1];
				p[j+1]=c;
				c=tmp[j];
				tmp[j]=tmp[j+1];
				tmp[j+1]=c;
			}*/
  for (k=2; k<=size; k=2*k) {
    for (j=k>>1; j>0; j=j>>1) {
      for (i=0; i<size; i++) {
	int ij=i^j;
	if ((ij)>i) {
	  if ((i&k)==0 && p[i] > p[ij]){
		c=p[i];
		p[i]=p[ij];
		p[ij]=c;
		c=tmp[i];
		tmp[i]=tmp[ij];
		tmp[ij]=c;
	  }
	  if ((i&k)!=0 && p[i] < p[ij]){
                c=p[i];
                p[i]=p[ij];
                p[ij]=c;
                c=tmp[i];
                tmp[i]=tmp[ij];
                tmp[ij]=c;
	  }
	}
      }
    }
  }
	arr=(void*)tmp;

}

int* ecall_chAddress(void *a)
{
	int tmp=*((int*)a);
	a=&tmp;
	return (int*)a;
}

/* ecall_sgx_cpuid:
 *   Uses sgx_cpuid to get CPU features and types.
 */
void ecall_sgx_cpuid(int cpuinfo[4], int leaf)
{
    sgx_status_t ret = sgx_cpuid(cpuinfo, leaf);
    if (ret != SGX_SUCCESS)
        abort();
}
