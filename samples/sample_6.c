#include <stdio.h>
#include <math.h>

int main(void)
{
  float a=0.6;
  float b=0.5;
  float results;

  results = remainderf(a, b);

  printf("reminder %0.1f\n",results);
}
