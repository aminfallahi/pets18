#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <immintrin.h>
void _main(){
int x;
                while (x<100000){x++;
                        printf("%d\n",x);}

}
int helperThread(){int exitCode=0;
        pid_t p;
        p=fork();
        if (p==0){
		_main();
                kill(getppid(),SIGKILL);
        }
        else{
		int *m;
                unsigned status;
                status=_xbegin();
                if (status == _XBEGIN_STARTED){
                while (1==1){{int j;}}
                        _xend();
                }
                else {exitCode=1; kill(p,SIGKILL);}
        }
return exitCode;
}
void main(){
printf("\n%d\n",helperThread());
}

