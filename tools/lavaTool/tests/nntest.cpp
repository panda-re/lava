#include <stdio.h>
#include "omg.h"

int main(int argc, char* argv[]) {
    if (argc <2 ) {
        printf("usage %s query\n", argv[0]);
        return 1;
    }
    std::string test = std::string(argv[1]);
    std::string res;
    res = createNonNullTests(test);

    printf("INPUT: %s => OUTPUT: %s\n", test.c_str(), res.c_str());
}
