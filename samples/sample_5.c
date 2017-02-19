#include <unistd.h>

int main(void)
{
    if (write(1, "This will be output to standard out\n", 36) != 36) {
        write(2, "There was an error writing to standard out\n", 44);
        return -1;
    }

    return 0;
}
