#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  char pattern[20];
  char *pass = "blah";

  if(argc == 3) {
    if(strcmp(pass, argv[1])) {
      strncpy(pattern, argv[2], 19);
    }
  }

return 0;
}
