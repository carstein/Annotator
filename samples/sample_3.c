#include <string.h>

int main(int argc, char*argv[])
{
  char str[]={"BBBABBB"};
  int c = 0x41;

  return (int)strchr(str, c);
}
