#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int f1 = 3;

char * f2;

extern int f4;

int test(int, int);

static int f5;

void test1(char *buf, int size)
{
    char temp = malloc(size);
    if (!temp)
        return;
    void *loc = memcpy(temp, buf, size);

    printf("You entered: %s\n", buf);
    return;
}

double f3;

int test2(int a, int b) {
    return (a+b);
}


int main(int argc, char **argv) {
    char buf[16] = {};

    if (argc < 2) {
        fprintf(stderr, "usage: %s <arg>\n", argv[0]);
        return 1;
    }
    
    memcpy(buf, argv[1], strlen(argv[1]));
    
    test1(buf, 16);

    test2(3, 5);

    int a = 3;
    int b = 5;

    test2(a, b);

    return 0;
}
