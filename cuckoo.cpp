#include "cuckoo.h"
#include <cassert>
#include <iostream>

size_t CuckooHashTable::size(){
  return table1.size();
}
CuckooHashTable::CuckooHashTable(std::vector<int> keys):
  num_elements(keys.size()),
  table_size(keys.size() * RESIZE_FACTOR),
  random{},
  hash1(HashFunc(keys.size() * RESIZE_FACTOR, random(), random())),
  hash2(HashFunc(keys.size() * RESIZE_FACTOR, random(), random())) {
  table1 = std::vector<int>(table_size, -1);
  table2 = std::vector<int>(table_size, -1);
  for (int key : keys){
    insert(key);
  }
}


void CuckooHashTable::build(std::vector<int> keys){ 
  num_elements = keys.size();
  table_size = num_elements * resize_factor;
  hash1 = HashFunc(table_size, random(), random());
  hash2 = HashFunc(table_size, random(), random());
  table1 = std::vector<int>(table_size, -1);
  table2 = std::vector<int>(table_size, -1);
  for (int key : keys){
    insert(key);
  }
}

// Increases num elements
void CuckooHashTable::insert(int key){
  assert(key != -1);
  num_elements++;
  if ((double) num_elements / (table_size * 2) > load_factor){
    resize(table_size * resize_factor);
  }
  bool empty = false;
  int attempts = 0;
  while (!empty){
    if (attempts > num_retries) {
      resize(table_size * resize_factor);
      attempts = 0;
    }
    int index = hash1.hash(key);
    if (table1[index] == -1) {
      table1[index] = key;
      return;
    }    
    int new_key = table1[index];
    table1[index] = key;
    
    index = hash2.hash(new_key);
    if (table2[index] == -1){
      table2[index] = new_key;
      return;
    }
    int key = table2[index];
    table2[index] = new_key;
    attempts += 2;
  }
}

void CuckooHashTable::resize(int new_table_size){
  table_size = new_table_size;
  hash1 = HashFunc(table_size, random(), random());
  hash2 = HashFunc(table_size, random(), random());
  hash1.print_params();
  hash2.print_params();
  std::vector<int> old_keys;
  for (int key : table1) {
    if (key != -1) old_keys.push_back(key);
  }
  for (int key : table2) {
    if (key != -1) old_keys.push_back(key);
  }
  table1 = std::vector<int>(table_size, -1);
  table2 = std::vector<int>(table_size, -1);
  num_elements = 0;
  for (int key : old_keys){
    insert(key);
  }
}

std::pair<int,int> CuckooHashTable::get(int key){

  if (table1[hash1.hash(key)] == key) return {hash1.hash(key), -1};
  if (table2[hash2.hash(key)] == key) return {-1, hash2.hash(key)};
  return {-1,-1};
}

void CuckooHashTable::print_table(){
  std::cout<< " == Cuckoo Table == " << std::endl;
  std::cout<< "Table 1: [ " ;
  for (int i = 0; i < table1.size() - 1; i++){
    std::cout << table1[i] << ", ";
  }
  std::cout << table1.back() << " ]" << std::endl;
  std::cout<< "Table 2: [ " ;
  for (int i = 0; i < table2.size() - 1; i++){
    std::cout << table2[i] << ", ";
  }
  std::cout << table2.back() << " ]" << std::endl;


}

  std::pair<HashFunc, HashFunc> CuckooHashTable::get_hash_funcs(){
    return {hash1, hash2};
  }