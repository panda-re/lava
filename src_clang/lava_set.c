static unsigned int lava_val[10000] = {0};
void lava_set(unsigned int idx, unsigned int val);
void lava_set(unsigned int idx, unsigned int val) { lava_val[idx % 10000] = val; }
unsigned int lava_get(unsigned int idx);
unsigned int lava_get(unsigned int idx) { return lava_val[idx % 10000]; }
