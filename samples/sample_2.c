#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  int ln = 0;

  if(argc == 2) {
    exit(strlen(argv[1]));
  }
  else
  {
    exit(-1);
  }
}
