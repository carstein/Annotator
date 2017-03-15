#include <math.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    double x, r;

    x = strtod(argv[1], NULL);
    r = ynf(5, x);

    printf("Result %0.1f\n",r);
    exit(EXIT_SUCCESS);
}
