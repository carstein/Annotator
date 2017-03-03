#include <string.h>

int main(int argc, char*argv[])
{
  char str[]={"BBBABBB"};
  int c = 0x41;
  char *p;

  p = strchr(str, c);

  return 0;
}
