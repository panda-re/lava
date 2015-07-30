static unsigned int lava_val = 0;
void lava_set(unsigned int val);
void lava_set(unsigned int val) { lava_val = val; }
unsigned int lava_get(void);
unsigned int lava_get(void) { return lava_val; }
