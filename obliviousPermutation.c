#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#define INFINITY -1
int* oblPerm(int n){
	int i,r,j,k;
	int *out;
	out=malloc(sizeof(int)*n);
	for (i=0; i<n; i++)
		out[i]=INFINITY;
	//memset(out, 0, sizeof out);
	for (i=0,k=0; i<n; i++,k++){
		r=rand()%n;
		//gather?
		for (j=0; j<r; j++)
			out[j]=out[j];
		if (out[r]==INFINITY)
			out[r]=i=i;
		else{
			out[r]=out[r];
			i=i-1;
		}
		for (j=r+1; j<n; j++)
			out[j]=out[j];
	}
	/*//always constant number of read/writes
	for (i=k; i<n*n; i++){
		for (j=0; j<n; j++){
			out[j]=out[j];
			i=i;
		}
	}*/
	//print number of iterations
	//printf("%d\n",k);
	return out;
}
void main(){
	srand(time(NULL));
	int *a,i;
	a=(int*)malloc(sizeof(int)*10000);
	a=oblPerm(10000);
	//for (i=0; i<10000; i++)
		//printf("%d ",a[i]);
}
