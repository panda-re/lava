#include <stdio.h>
static unsigned int lava_val[1000000] = {0};
void lava_set(unsigned int bug_num, unsigned int val);
__attribute__((visibility("default"))) void lava_set(unsigned int bug_num, unsigned int val) { lava_val[bug_num] = val; }
unsigned int lava_get(unsigned int trigger_id, unsigned int bug_id, unsigned int trigger);
__attribute__((visibility("default"))) unsigned int lava_get(unsigned int trigger_id, unsigned int bug_id, unsigned int trigger) { 
    if (lava_val[trigger_id] == trigger) {
        printf("[LAVA] bug %d causes a crash\n", bug_id);
    }
    return lava_val[trigger_id]; 
}
