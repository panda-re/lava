#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <algorithm>
#include <iostream>

std::vector<std::string> InvertDB(std::map<std::string, uint32_t> &n2ind) {
    std::vector<std::string> ind2n;
    uint32_t max_index = 0;
    for ( auto kvp : n2ind ) {
        max_index = std::max(max_index, kvp.second);
    }
    ind2n.resize(max_index + 1);
    for ( auto kvp : n2ind ) {
        ind2n[kvp.second] = kvp.first;
    }
    return ind2n;
}

std::map<std::string,uint32_t> LoadDB(std::string dbfile) {
    // Parse the db
    std::map<std::string,uint32_t> StringIDs;
    std::ifstream db(dbfile);
    std::string line;
    while (std::getline(db, line)) {
        size_t delimiterPos = line.find('\t');
        if (delimiterPos != std::string::npos) {
            std::string istr = line.substr(0, delimiterPos); // Extract the ID part
            std::string str = line.substr(delimiterPos + 1); // Extract the string part
            std::cout << "Loading " << str << " with ID " << istr << std::endl;
            StringIDs[str] = strtoul(istr.c_str(), NULL, 0);
        }
    }

    return StringIDs;
}

void SaveDB(const std::map<std::string, uint32_t> &StringIDs, std::string dbfile) {
    std::ofstream db(dbfile);

    // 1. Copy map pairs to a vector
    std::vector<std::pair<std::string, uint32_t>> sorted_vec(StringIDs.begin(), StringIDs.end());

    // 2. Sort the vector based on the ID (the .second element)
    std::sort(sorted_vec.begin(), sorted_vec.end(),
        [](const auto &a, const auto &b) {
            return a.second < b.second;
        }
    );

    // 3. Write to the database file
    for (const auto &p : sorted_vec) {
        db << p.second << '\t' << p.first << '\n';
    }
    std::cout << "Saved LavaDB (Sorted by ID)" << std::endl;
}

uint32_t GetStringID(std::map<std::string, uint32_t> &StringIDs, std::string s) {
    std::map<std::string, uint32_t>::iterator it;
    // This does nothing if s is already in StringIDs.
    std::tie(it, std::ignore) = StringIDs.insert(std::make_pair(s, StringIDs.size()));
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
