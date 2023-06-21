#pragma once

#include "pir_server.h"
#include "cuckoo.h"

class keyword_pir_server_single : public pir_server{
  public:
  keyword_pir_server_single(const seal::EncryptionParameters &params, const PirParams &pir_params):
  pir_server(params, pir_params){}
  void set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&db, std::vector<bool> membership_table);
  PirReply generate_reply(PirQuery query, uint32_t client_id, SecretKey sk);

  private:
  // Tracks which indexes are empty and which have entries
  std::vector<bool> membership_table_;

};

class keyword_pir_server {
  public:
  keyword_pir_server(const seal::EncryptionParameters &params, const PirParams &pir_params):
  sv1_(params, pir_params),
  sv2_(params, pir_params),
  params_(params),
  pir_params_(pir_params){}

  std::pair<HashFunc, HashFunc> get_hashes(){
    return cuckoo_table_.get_hash_funcs();
  }

  /* Set up a database with data passed in as a vector of pairs of <keyword, data>. We assume that all the data fits into a single plaintext and do not pack multiple entries into a single plaintext. */
  void set_database(const std::vector<std::pair<int, std::vector<std::uint8_t>>> & entries);
  std::pair<PirReply, PirReply> generate_reply(std::pair<PirQuery, PirQuery> query, uint32_t client_id, SecretKey sk);
  void set_enc_sk(GSWCiphertext sk_enc);
  void set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey);

  private:
    seal::EncryptionParameters params_; // SEAL parameters
    PirParams pir_params_;// PIR parameters
  CuckooHashTable cuckoo_table_;
  keyword_pir_server_single sv1_;
  keyword_pir_server_single sv2_;
};
