#pragma once

#include "pir_client.h"
#include "cuckoo.h"
#include <stdexcept>


class keyword_pir_client : public pir_client {
  public:
  keyword_pir_client(const seal::EncryptionParameters &parms,
              const PirParams &pirparms): pir_client(parms, pirparms){}
  void set_hashes(std::pair<HashFunc, HashFunc> hashes){
    hash1 = hashes.first;
    hash2 = hashes.second;
    hash_funcs_set = true;
  }

  std::pair<PirQuery, PirQuery> generate_query(std::uint64_t keyword){
    if (!hash_funcs_set) {
      throw std::invalid_argument("Hash functions not set");
    }
    return {pir_client::generate_query(hash1.hash(keyword)), pir_client::generate_query(hash2.hash(keyword))};
  }

  std::pair<Plaintext, Plaintext> decrypt_result(std::pair<PirReply, PirReply> reply){
    return {pir_client::decrypt_result(reply.first), pir_client::decrypt_result(reply.second)};
  }


  private:
  HashFunc hash1 = HashFunc(1,1,1);
  HashFunc hash2 = HashFunc(1,1,1);
  bool hash_funcs_set = false;
  
};