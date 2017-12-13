#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
//#include "rtm.h"
#include <immintrin.h>
void mainFunc(){
}
void globalize(){
}
void main(){
	int a,fd[2];
	pipe(fd);
	pid_t p;
	p=fork();
	if (p==0){
		a=1;
		while (a<1000){//a++;
			printf("+++");}
		kill(getppid(),SIGKILL);
	}
	else{
		a=2;
		int returnStatus;
		unsigned status;
		status=_xbegin();
		if (status == _XBEGIN_STARTED){
			//waitpid(p,&returnStatus,0);
                while (1==1){a++; 
                        }
			a=3;
			_xend();
		}
		else {a=4; kill(p,SIGKILL);}
	}
printf("\n%d\n",a);
}

