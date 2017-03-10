#ifndef __LAVA_DB_H_
#define __LAVA_DB_H_

#include <cstdint>
#include <map>
#include <string>

// save a string -> index db to file
void SaveDB(const std::map<std::string,uint32_t> &StringIDs, std::string dbfile);

// load a string -> index db from file
std::map<std::string,uint32_t> LoadDB(std::string dbfile);

// invert to get index -> string db
std::map<uint32_t,std::string> InvertDB(std::map<std::string,uint32_t> &n2ind);

// Add string to DB or return existing ID.
uint32_t GetStringID(std::map<std::string, uint32_t> &StringIDs, std::string s);

#endif
