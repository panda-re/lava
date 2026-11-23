/* File-input main for upstream LLVMFuzzerTestOneInput harnesses.
 * This is LAVA support code, not part of the upstream source tarballs.
 * Keep the upstream callback and optional initializer unchanged.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerInitialize(int *, char ***) __attribute__((weak));
extern int LLVMFuzzerTestOneInput(const uint8_t *, size_t);

int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
    if (argc != 2) {
        fprintf(stderr, "usage: %s INPUT\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    if (fseek(f, 0, SEEK_END)) {
        return 2;
    }
    long length = ftell(f);
    if (length < 0 || fseek(f, 0, SEEK_SET)) {
        return 2;
    }
    size_t size = (size_t)length;
    uint8_t *data = malloc(size ? size : 1);
    if (!data) {
        return 2;
    }
    if (fread(data, 1, size, f) != size) {
        return 2;
    }
    fclose(f);
    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}
