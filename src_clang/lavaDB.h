#ifndef __LAVA_DB_H_
#define __LAVA_DB_H_

// save a string -> index db to file
void SaveDB(std::map<std::string,uint32_t> StringIDs, std::string dbfile);

// load a string -> index db from file
std::map<std::string,uint32_t> LoadDB(std::string dbfile);

// invert to get index -> string db
std::map<uint32_t,std::string> InvertDB(std::map<std::string,uint32_t> &n2ind);

#endif
