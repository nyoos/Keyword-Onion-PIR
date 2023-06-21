#pragma once

#include <utility>
#include <vector>
#include <random>

#define RESIZE_FACTOR 2
#define HASH_PRIME (1L << 61) - 1

  // A two-wise independent hash function. Output ranges from 0 to m - 1.
  class HashFunc{
    public: 
      HashFunc(unsigned int m , unsigned int a, unsigned int b):
        m(m),
        a( a % HASH_PRIME),
        b( b % HASH_PRIME),
        p(HASH_PRIME){
        }

      unsigned int hash(int key){
        return (a * key + b) % p % m;
      }

      void print_params(){
        printf("a: %lu, b: %lu, m: %lu, p: %lu\n", a, b, m, p);
      }

    private:
      uint64_t p;
      uint64_t m;
      uint64_t a;
      uint64_t b;
  };

class CuckooHashTable{
  public:


  CuckooHashTable():
  random(),
  hash1(HashFunc(10, random(), random())),
  hash2(HashFunc(10, random(), random())){
  }
  CuckooHashTable(std::vector<int> keys);
  
  /* Builds a new cuckoo hash table with the given values */
  void build(std::vector<int> keys);

  /* Resizes an existing cuckoo hash table such that each table now has size table_size */
  void resize(int new_table_size);

  /* Inserts an element and resizes the table where necessary */
  void insert(int key);
  int & get_num_retries() {
    return num_retries;
  }
  
  /* Given a key, if key is in one of the tables, returns a pair {index, -1} if it is in table 1 or {-1, index} if it is in table 2. Otherwise return {-1, -1} */
  std::pair<int, int> get(int key);


  /* Returns the two hash functions */
  std::pair<HashFunc, HashFunc> get_hash_funcs();
  void print_table();

  /* Returns size of a single table */
  size_t size();


  private:


  HashFunc hash1;
  HashFunc hash2;
  std::vector<int> table1;
  std::vector<int> table2;
  double load_factor = 0.5;
  int num_elements = 10;
  // Size of each individual table
  int table_size = 10;
  int num_retries = 200;
  // How much to increase the table size each time the load factor is exceeded
  int resize_factor = RESIZE_FACTOR;
  std::mt19937_64 random;
};