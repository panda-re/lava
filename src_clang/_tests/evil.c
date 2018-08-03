#ifdef DEBUG
#include <stdio.h>
#include <stdarg.h>
#endif

int myprintf (const char *format, ...) __attribute__ ((format (printf, 1, 0)));

int myprintf (const char *fmt, ...) {
    int done=1;
    #ifdef DEBUG
        va_list arg;
        va_start (arg, fmt);
        vprintf (fmt, arg); // This is actually broken
        va_end(arg);
    #endif
    return done;
}

void normal_fn_call() {
    myprintf("In normal_fn_call\n");
}
void normal_fn_call_void(void) {
    myprintf("In normal_fn_call_void\n");
}

int normal_fn_call_arg(int arg) {
    myprintf("In normal_fn_call_arg with arg=%d\n", arg);
    return arg + __LINE__;
}

int normal_fn_call_2arg(int arg1, int arg2) {
    myprintf("In normal_fn_call_arg with arg1=%d, arg2=%d\n", arg1, arg2);
    return arg1 + __LINE__;
}

int ptr_fn(int arg) {
    myprintf("In fn_ptr with arg=%d\n", arg);
    return arg + __LINE__;
}

int ptr_fn1(int arg) {
    myprintf("In fn_ptr1 with arg=%d\n", arg);
    return arg + __LINE__;
}

int ptr_fn2(int arg) {
    myprintf("In fn_ptr2 with arg=%d\n", arg);
    return arg + __LINE__;
}

int ptr_fn3(int arg) {
    myprintf("In fn_ptr3 with arg=%d\n", arg);
    return arg + __LINE__;
}

int ptr_fn4(int arg) {
    myprintf("In fn_ptr4 with arg=%d\n", arg);
    return arg + __LINE__;
}

typedef int (*fun_ptr_typedef)(int) ;

struct PtrStr {
    fun_ptr_typedef typedef_fn_ptr;
    int(*fn_ptr)(int);
};

int main(int argc, char *argv[]) {
    int result = 0;
    int i;

    // No args and (void) arg
        normal_fn_call();
        normal_fn_call_void();

    // Functions with args
        result = normal_fn_call_arg(result);
        result = normal_fn_call_2arg(result, result);

    // Function pointer - two ways to call
        int (*fun_ptr)(int) = &ptr_fn;
        result = (*fun_ptr)(result);
        result = fun_ptr(result);

    // Typedefed function pointer
        fun_ptr_typedef ptr_fn_typedef = &ptr_fn;
        result = (*ptr_fn_typedef)(result);

    // Array of typedefd function pointers
        fun_ptr_typedef ptr_fn_typedef_array[2] = {ptr_fn1, ptr_fn2};

        for (i=0; i<2; i++) {
            result = (*ptr_fn_typedef_array[i])(result);
        }

    //Struct tests
        struct PtrStr str;

        //Struct test- typedefed
            str.typedef_fn_ptr = &ptr_fn3;
            result = str.typedef_fn_ptr(result);

        //Struct test- function pointer
            str.fn_ptr = &ptr_fn4;
            result = str.fn_ptr(result);

    myprintf("End of main: result = %d\n", result); // Expecting 103
    return (result==121);
}
