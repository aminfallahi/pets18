#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
//#include "rtm.h"
#include <immintrin.h>
void main(){
	int status=_xbegin();
	printf("%d",status);
	if (status==_XBEGIN_STARTED){
		printf("something");
		_xend();
	}
}

