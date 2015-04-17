#include <map>
#include <string>
#include <fstream>
#include <stdlib.h>
#include <stdint.h>

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

void SaveDB(std::map<std::string,uint32_t> StringIDs, std::string dbfile) {
    FILE *f = fopen(dbfile.c_str(), "wb");
    for (auto p : StringIDs) {
        fprintf(f, "%u", p.second);
        fwrite("\0", 1, 1, f);
        fprintf(f, "%s", p.first.c_str());
        fwrite("\0", 1, 1, f);
    }
    fclose(f);
}

#ifdef DBTEST
int main(int argc, char **argv) {
    std::map<std::string,uint32_t> db = LoadDB(argv[1]);
    for (auto p : db) {
        printf ("%s => %u\n", p.first.c_str(), p.second);
    }
    db["my_test_string"] = db.size();
    SaveDB(db, argv[2]);
    return 0;
}
#endif
