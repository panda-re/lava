#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <tuple>

std::map<uint32_t,std::string> InvertDB(std::map<std::string,uint32_t> &n2ind) {
    std::map<uint32_t,std::string> ind2n;
    for ( auto kvp : n2ind ) {
        ind2n[kvp.second] = kvp.first;
    }
    return ind2n;
}

std::map<std::string,uint32_t> LoadDB(std::string dbfile) {
    // Parse the db
    std::map<std::string,uint32_t> StringIDs;
    std::ifstream db(dbfile);
    if (db.is_open()) {
        std::string str;
        std::string istr;
        while (std::getline(db, istr, '\0')) {
            std::getline(db, str, '\0');
            StringIDs[str] = strtoul(istr.c_str(), NULL, 0);
        }
    }

    return StringIDs;
}

void SaveDB(const std::map<std::string,uint32_t> &StringIDs, std::string dbfile) {
    std::ofstream db(dbfile);
    for (auto p : StringIDs) {
        db << p.second << '\0' << p.first << '\0';
    }
}

uint32_t GetStringID(std::map<std::string, uint32_t> &StringIDs, std::string s) {
    std::map<std::string, uint32_t>::iterator it;
    // This does nothing if s is already in StringIDs.
    std::tie(it, std::ignore) =
        StringIDs.insert(std::make_pair(s, StringIDs.size()));
    return it->second;
}

#ifdef DBTEST
int main(int argc, char **argv) {
    std::map<std::string,uint32_t> db = LoadDB(argv[1]);
    for (auto p : db) {
        printf ("%s => %u\n", p.first.c_str(), p.second);
    }
    return 0;
}
#endif
