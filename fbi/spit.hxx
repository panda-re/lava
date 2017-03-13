#ifndef __FBI_SPIT_HXX
#define __FBI_SPIT_HXX

#include <cstdint>
#include <vector>
#include <string>

extern std::vector<std::string> ind2str;

static void spit_tquls(const Panda__TaintQueryUniqueLabelSet *tquls) {
    printf("tquls=[ptr=0x%" PRIx64 ",n_label=%d,label=[", tquls->ptr, (int) tquls->n_label);
    for (uint32_t i=0; i<tquls->n_label; i++) {
        printf("%d", tquls->label[i]);
        if (i+1<tquls->n_label) printf(",");
    }
    printf("]]");
}

static void spit_tq(Panda__TaintQuery *tq) {
    printf("tq=[ptr=0x%" PRIx64 ",tcn=%d,offset=%d]", tq->ptr, tq->tcn, tq->offset);
}

static void spit_si(Panda__SrcInfo *si) {
    printf("si=[filename='%s',line=%d,", (char*) ind2str[si->filename].c_str(), si->linenum);
    printf("astnodename='%s',", (char *) ind2str[si->astnodename].c_str());
    if (si->has_insertionpoint) {
        printf("insertionpoint=%d", si->insertionpoint);
    }
    printf("]");
}

static void spit_tqh(Panda__TaintQueryHypercall *tqh) {
    printf("tqh=[buf=0x%" PRIx64 ",len=%d,num_tainted=%d]", tqh->buf, tqh->len, tqh->num_tainted);
}

static void spit_ap(Panda__AttackPoint *ap) {
    printf("ap=[info=%d]", ap->info);
}

#endif
