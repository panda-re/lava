#include <stddef.h>
#include <signal.h>

int foo(int x, float y);
int v(void);


int v(void) {
    return 0;
}

int bar(int (*fp)(int, float), int a, float b) {
    return fp(a, a+b);
}

int foo(int x, float y) {
    if (x < 12) return foo(x*x, y/x);
    return foo(x-1, x+y);
}

int foo2(int x, float y) {
    if (x < 12) return foo(x*x, y/x);
    return foo(x-1, x+y);
}

int main(int argc, char**argv) { 

    sig_t foobar;
    
    // Conditional function pointer init + assign
    int (*fun_ptr)(int, float) = (argc>2) ? (foo) : (foo2);
    int (*fp)(int, float);
    fp = foo;

    foobar = signal(13, ((__sighandler_t) 1));
    (void)signal(13, foobar);
 
    int y = fp(3,7.4) 
        + bar(foo, 3, 9.9)
        + bar(fp, 66, 0.33);
    return foo(fun_ptr(y, 33), 7.2); 
}
