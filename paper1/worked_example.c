void foo(int a, int b, char *s, char *d, int n) {
    int c = a+b;
    if (a != 0xdeadbeef) 
        return;  
    for (int i=0; i<n; i++) 
        c+=s[i];
    memcpy(d,s,n+c); // Original source
    // BUG: memcpy(d+(b==0x6c617661)*b,s,n+c);
}  
