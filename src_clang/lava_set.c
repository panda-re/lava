static unsigned int lava_val[1000000]; static int lava_first=1;
void lava_set(unsigned int bug_num, unsigned int val);
void lava_set(unsigned int bug_num, unsigned int val) { if (lava_first) {int i; lava_first=0; for (i=0; i<1000000; i++) lava_val[i]=0; }  lava_val[bug_num] = val; }
unsigned int lava_get(unsigned int bug_num);
unsigned int lava_get(unsigned int bug_num) { return lava_val[bug_num]; }
