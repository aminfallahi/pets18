#include <stdlib.h>
#include <immintrin.h>
#include <stdio.h>
int *g;
void main(){
	int status=_xbegin();
	if (status == _XBEGIN_STARTED) {
		printf("0000");
		_xend();
	}
	else{
		printf("fault1\n");
}

        status=_xbegin();
        if (status == _XBEGIN_STARTED) {
                printf("0000");
		_xend();
        }
        else{
		printf("fault2\n");
}

}

