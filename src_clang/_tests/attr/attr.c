int testfn (int x, const char *format, ...) __attribute__ ((format (printf, 2, 0)));
int __attribute__ ((__nothrow__)) testfn2 (int x, const char *format, ...) __attribute__ ((format (printf, 2, 0)));

int testfn(int x, const char *format, ...) {
    return x+1;
}

int testfn2(int x, const char *format, ...) {
    return x+2;
}


int main() {
    int result = 0;
    result = testfn(result, "%s", "Hello");
    result = testfn2(result, "%x", 41);

    return (result==3);
}
