#include<stdlib.h>
#include<immintrin.h>
#include<stdio.h>
void main(){
int x=10,y=10;
int status = _xbegin();
if (status == _XBEGIN_STARTED) {
x++;
printf("000");
_xend();
} else {
printf("111");
 x--;
}
//printf("%d",x);
status = _xbegin();
if (status == _XBEGIN_STARTED) {
printf("000");
y++;
_xend();
} else {
printf("111");
y--;
}
printf ("\n%d %d\n",x,y);
}
