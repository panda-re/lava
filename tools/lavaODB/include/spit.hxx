#ifndef __FBI_SPIT_HXX
#define __FBI_SPIT_HXX

#include <cstdint>
#include <vector>
#include <string>

extern std::vector<std::string> ind2str;

static void spit_tquls(Json::Value& tquls) {
    uint32_t n_label = tquls["label"].size();
    printf("tquls=[ptr=0x%" PRIx64 ",n_label=%u,label=[", std::strtoul(tquls["ptr"].asString().c_str(), 0, 0), n_label);

    int i = 0;
    for (Json::Value& element : tquls["label"]) {
		printf("%lu", std::strtoul(element.asString().c_str(), 0, 0));
        if (i + 1 < n_label) {
            printf(",");
        }
        ++i;
	}
    printf("]]");
}

static void spit_tq(const Json::Value& tq) {
    printf("tq=[ptr=0x%" PRIx64 ",tcn=%lu,offset=%lu]",
        std::strtoul(tq["ptr"].asString().c_str(), 0, 0), 
        std::strtoul(tq["tcn"].asString().c_str(), 0, 0), 
        std::strtoul(tq["offset"].asString().c_str(), 0, 0));
}

static void spit_si(const Json::Value& si) {
    printf("si=[filename='%s',line=%lu,", si["filename"].asString().c_str(), std::strtoul(si["linenum"].asString().c_str(), 0, 0));
    printf("astnodename='%s',", si["astnodename"].asString().c_str());
    if (si.isMember("insertionpoint")) {
        printf("insertionpoint=%lu", std::strtoul(si["insertionpoint"].asString().c_str(), 0, 0));
    }
    printf("]");
}

static void spit_tqh(const Json::Value& tqh) {
    printf("tqh=[buf=0x%" PRIx64 ",len=%lu,num_tainted=%lu]", 
        std::strtoul(tqh["buf"].asString().c_str(), 0, 0),
        std::strtoul(tqh["len"].asString().c_str(), 0, 0),
        std::strtoul(tqh["num_tainted"].asString().c_str(), 0, 0));
}

static void spit_ap(const Json::Value& ap) {
    printf("ap=[info=%lu]", std::strtoul(ap["info"].asString().c_str(), 0, 0));
}

#endif
