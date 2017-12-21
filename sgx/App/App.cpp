#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
//#include "sgx_status.h"
#include "App.h"
#include "Enclave_u.h"
#include <time.h>
#include <signal.h>
#include <immintrin.h>
#include <resource.h>

int ecall_foo1(int i)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval;
	int index;
	int arrsize = 100000;
	//	char a[10000][100];//=(int*)malloc(sizeof(int)*arrsize);
	//	char b[10000][100];
	//	int b[10000];
	int* a = (int*) malloc(sizeof(int)*arrsize);

	FILE* fp;
	char* line;
	size_t len = 0;
	fp = fopen("datasets/randInt100000-1", "r");
	index = 0;
	while ((getline(&line, &len, fp)) != -1) {
		a[index] = atoi(line);
		//printf("%d ",a[index]);
		//		strcpy(a[index],line);
		index++;
		if (index > arrsize) break;
	}

	/*	for (index=0; index<arrsize; index++){
			a[index]=rand()%arrsize;
	//		printf("%d ",a[index]);
		}*/
	clock_t begin = clock();
	//        ecall_shuffle(global_eid,(void*)a,arrsize);
	ecall_mergeSort(global_eid, (void*) a, 0, arrsize - 1);
	//	ecall_sortStrings(global_eid,a,10000);
	clock_t end = clock();
	double time_spent = (double) (end - begin) / CLOCKS_PER_SEC;
	printf("%lf\n", time_spent);
	//	for (index=0; index<100000; index++)
	//		printf("%d ",a[index]);

	//    ret = ecall_foo(global_eid, &retval, i);
	//    ret = ecall_amin(global_eid, &retval, 100);
	/*	int *a = (int*) malloc(sizeof(int)*128);
		for (i = 0; i < 128; i++) a[i] = i;
		int x = 3;
		ret = ecall_intAccess(global_eid, &retval, &a[0], 50, 128);
		printf("retete %d\n", retval);*/
	/*    int j, *a;
	    a = (int*) malloc(sizeof (int)*10000);
	    for (j = 0; j < 100; j++)
		a[j] = j;
	    ecall_shuffle(global_eid, (void*) a, 100);
	    if (ret != SGX_SUCCESS)
		abort();

	    int cpuid[4] = {0x1, 0x0, 0x0, 0x0};
	    ret = ecall_sgx_cpuid(global_eid, cpuid, 0x0);
	    if (ret != SGX_SUCCESS)
		abort();*/
	return retval;
}







/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
	{
		SGX_ERROR_UNEXPECTED,
		"Unexpected error occurred.",
		NULL
	},
	{
		SGX_ERROR_INVALID_PARAMETER,
		"Invalid parameter.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_MEMORY,
		"Out of memory.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_LOST,
		"Power transition occurred.",
		"Please refer to the sample \"PowerTransition\" for details."
	},
	{
		SGX_ERROR_INVALID_ENCLAVE,
		"Invalid enclave image.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ENCLAVE_ID,
		"Invalid enclave identification.",
		NULL
	},
	{
		SGX_ERROR_INVALID_SIGNATURE,
		"Invalid enclave signature.",
		NULL
	},
	{
		SGX_ERROR_OUT_OF_EPC,
		"Out of EPC memory.",
		NULL
	},
	{
		SGX_ERROR_NO_DEVICE,
		"Invalid SGX device.",
		"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
	},
	{
		SGX_ERROR_MEMORY_MAP_CONFLICT,
		"Memory map conflicted.",
		NULL
	},
	{
		SGX_ERROR_INVALID_METADATA,
		"Invalid enclave metadata.",
		NULL
	},
	{
		SGX_ERROR_DEVICE_BUSY,
		"SGX device was busy.",
		NULL
	},
	{
		SGX_ERROR_INVALID_VERSION,
		"Enclave version was invalid.",
		NULL
	},
	{
		SGX_ERROR_INVALID_ATTRIBUTE,
		"Enclave was not authorized.",
		NULL
	},
	{
		SGX_ERROR_ENCLAVE_FILE_ACCESS,
		"Can't open enclave file.",
		NULL
	},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: retrive the launch token saved by last transaction */

	/* __GNUC__ */
	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL &&
		(strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}

	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		if (fp != NULL) fclose(fp);
		return -1;
	}

	/* Step 3: save the launch token if it is updated */
	/* __GNUC__ */
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}

/* OCall functions */
void ocall_bar(const char *str, int ret[1])
{
	/* Proxy/Bridge will check the length and null-terminate 
	 * the input string to prevent buffer overflow. 
	 */
	printf("%s", str);
	ret[0] = 13;
}

void ocall_tlbShootdown()
{
	pid_t p;
	p = fork();
	//if (p == 0);
	kill(p, SIGKILL);
}

/*main application code*/
void _main()
{
	/*	int a = 1;
		while (a < 100000) {a++;
			printf("%d\n",a);
		}*/
	int retVal;
	retVal = ecall_foo1(1);


}

/*executing application parallel to a helper thread*/
int helperThread()
{
	int exitCode = 0;
	long cs = 0;
	pid_t p;
	p = fork();
	if (p == 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(p, sizeof(cpu_set_t), &set);
		if (!_xtest)
			_main();
		kill(getppid(), SIGKILL);
	}
} else {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(1, &set);
	sched_setaffinity(getppid(), sizeof(cpu_set_t), &set);
	unsigned status;
	__asm__("FALLBACK:\r\n");
	status = _xbegin();
	if (status == _XBEGIN_STARTED) {
		while (1 == 1) {
			{
				int* dum = (int*) malloc(rand() % 1000);
				free(dum);
			}
		}
		_xend();
	} else {
		struct rusage * u;
		getrusage(RUSAGE_SELF, u);
		if (u->ru_nvcsw + u->ru_nivcsw > c) {
			c = u->ru_nvcsw + u->ru_nivcsw;
			__asm__("GOTO FALLBACK\r\n");
		}
		exitCode = 1;
		kill(p, SIGKILL);
	}
}
return exitCode;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	srand(time(NULL));
	/* Initialize the enclave */
	if (initialize_enclave() < 0) {
		printf("Error enclave and exit\n");
		return -1;
	}

	/* Utilize edger8r attributes */
	edger8r_function_attributes();
	ecall_foo1(1);
	//clock_t begin=clock();
	//helperThread();
	//clock_t end=clock();
	//double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	//printf("\nhelper %lf\n",time_spent);
	sgx_destroy_enclave(global_eid);
	return 0;
}


