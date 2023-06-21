#include "keyword_pir_server.h"

void keyword_pir_server::set_database(const std::vector<std::pair<int, std::vector<std::uint8_t>>> &entries){
  std::vector<int> keywords;
  for (auto & i : entries) {
    keywords.push_back(i.first);
  }
  cuckoo_table_ = CuckooHashTable(keywords);
  size_t num_plaintexts_needed = cuckoo_table_.size();

  // Set up the servers
  std::vector<Plaintext> data1(num_plaintexts_needed);
  std::vector<Plaintext> data2(num_plaintexts_needed);
  std::vector<bool> membership_table1(num_plaintexts_needed);
  std::vector<bool> membership_table2(num_plaintexts_needed);

  uint64_t bits_per_coeff = params_.plain_modulus().bit_count() - 1;
  uint64_t poly_degree = params_.poly_modulus_degree();
  for (auto & entry : entries) {
    // Encode the data into a plaintext
    uint128_t data_buffer = 0;
    uint8_t data_offset = 0;
    uint128_t coeff_mask = (1 << (bits_per_coeff + 1)) - 1;

    auto data_iterator  = entry.second.begin();
    auto end_iterator = entry.second.end();
    seal::Plaintext plaintext(poly_degree);
    for (int i = 0; i < poly_degree && data_iterator != end_iterator; ++i){ 
      for (int j = 0 ; j < bits_per_coeff && data_iterator != end_iterator; j += 8){
        data_buffer += *(data_iterator++) << data_offset;
        data_offset += 8;
      }
      plaintext[i] = data_buffer & coeff_mask;
      data_buffer >>= bits_per_coeff;
      data_offset -= bits_per_coeff;
      if (data_iterator == end_iterator){
        if (data_buffer != 0) {
          plaintext[i+1] = data_buffer;
        }
      }
    }
    
    auto index = cuckoo_table_.get(entry.first);
    if (index.first != -1){
      data1[index.first] = plaintext;
      membership_table1[index.first] = true;
    } else if (index.second != -1){
      data2[index.second] = plaintext;
      membership_table2[index.second] = true;
    } else {
      throw std::exception();
    }
  }

  sv1_.set_database(make_unique<std::vector<Plaintext>>(move(data1)), membership_table1);
  sv2_.set_database(make_unique<std::vector<Plaintext>>(move(data2)), membership_table2);
}


std::pair<PirReply, PirReply> keyword_pir_server::generate_reply(std::pair<PirQuery, PirQuery> query, uint32_t client_id, SecretKey sk) {
  return {sv1_.generate_reply(query.first, client_id, sk),
  sv2_.generate_reply(query.second, client_id, sk)};
}

void keyword_pir_server::set_enc_sk(GSWCiphertext sk_enc){
  sv1_.set_enc_sk(sk_enc);
  sv2_.set_enc_sk(sk_enc);
}

void keyword_pir_server::set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey){
  sv1_.set_galois_key(client_id, galkey);
  sv2_.set_galois_key(client_id, galkey);
}

void keyword_pir_server_single::set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&db, std::vector<bool> membership_table) {
  pir_server::set_database(move(db));
  membership_table_ = membership_table;
}

PirReply keyword_pir_server_single::generate_reply(PirQuery query, uint32_t client_id, SecretKey sk){

    assert(query.size()==2);

    Decryptor dec(newcontext_,sk);
    Plaintext pt;
    pt.resize(4096);
    pt.set_zero();
    //pt[0]=123;

    vector<uint64_t> nvec = pir_params_.nvec;


    uint64_t product = 1;

    for (uint32_t i = 0; i < nvec.size(); i++) {
        product *= nvec[i];

    }

    auto coeff_count = params_.poly_modulus_degree();


    vector<Plaintext> intermediate_plain; // decompose....

    auto pool = MemoryManager::GetPool();


    int N = params_.poly_modulus_degree();

    int logt = params_.plain_modulus().bit_count();

    vector<Ciphertext> first_dim_intermediate_cts(product/nvec[0]);


    for (uint32_t i = 0; i < 1; i++) {



        uint64_t n_i = nvec[i];
        cout << "Server: first dim size = " << n_i << endl;
        cout << "Server: expanding " << query[i].size() << " query ctxts" << endl;

            uint64_t total = n_i;

            cout << "-- expanding one query ctxt into " << total  << " ctxts "<< endl;

            vector<GSWCiphertext> list_enc;

        int decomp_size = params_.plain_modulus().bit_count() / pir_params_.plain_base;
            list_enc.resize(n_i, GSWCiphertext(decomp_size));
            vector<GSWCiphertext>::iterator list_enc_ptr = list_enc.begin();
        auto start = high_resolution_clock::now();

            //vector<Ciphertext> expanded_query_part = expand_query(query[i][j], total, client_id);

            //n_1=64
            poc_expand_flat(list_enc_ptr, query[i], newcontext_, n_i, galoisKeys_);




        //cout<<"tttttt=========="<<time_server_us/query[i].size()<<endl;
        //cout << "Server: expansion done " << endl;
        // cout << " size mismatch!!! " << expanded_query.size() << ", " << n_i << endl;
        if (list_enc.size() != n_i) {
            cout << " size mismatch!!! " << list_enc.size() << ", " << n_i << endl;
        }


        for (uint32_t jj = 0; jj < list_enc.size(); jj++)
        {


            poc_nfllib_ntt_gsw(list_enc[jj],newcontext_);


        }

        auto end = high_resolution_clock::now();
        int time_server_us =  duration_cast<milliseconds>(end - start).count();
        cout<<"Rlwe exansion time= "<<time_server_us<<" ms"<<endl;


        product /= n_i;

        vector<Ciphertext> intermediateCtxts(product);


        auto time_server_s = high_resolution_clock::now();


        int durrr =0;
        for (uint64_t k = 0; k < product; k++) {

            first_dim_intermediate_cts[k].resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
            poc_nfllib_external_product(list_enc[0], split_db[k], newcontext_, decomp_size, first_dim_intermediate_cts[k],1);

            for (uint64_t j = 1; j < n_i; j++) {

                uint64_t total = n_i;

                //cout << "-- expanding one query ctxt into " << total  << " ctxts "<< endl;


                Ciphertext temp;
                temp.resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);

                auto expand_start = high_resolution_clock::now();
                poc_nfllib_external_product(list_enc[j], split_db[k + j * product], newcontext_, decomp_size, temp,1);
                auto expand_end  = high_resolution_clock::now();

                evaluator_->add_inplace(first_dim_intermediate_cts[k], temp); // Adds to first component.
                //poc_nfllib_add_ct(first_dim_intermediate_cts[k], temp,newcontext_);


                 durrr = durrr+  duration_cast<microseconds>(expand_end - expand_start).count();
                //cout << "first-dimension cost" << durrr  << endl;


            }

        }


        cout << "first-dimension cost" << durrr/(product*n_i)  << endl;



       auto expand_start  = high_resolution_clock::now();

        for (uint32_t jj = 0; jj < first_dim_intermediate_cts.size(); jj++) {


            //evaluator_->transform_from_ntt_inplace(intermediateCtxts[jj]);
            poc_nfllib_intt_ct(first_dim_intermediate_cts[jj],newcontext_);

        }

        auto expand_end  = high_resolution_clock::now();
         durrr =  duration_cast<milliseconds>(expand_end - expand_start).count();
        cout << "INTT after first dimension" << durrr  << endl;


    }


    uint64_t  new_dimension_size=0, logsize;
    if(nvec.size()>1) {

        for (uint32_t i = 1; i < nvec.size(); i++) {
            new_dimension_size = new_dimension_size + nvec[i];
        }

        logsize = ceil(log2(new_dimension_size));

    }

    //testing starts from here
    vector<GSWCiphertext> CtMuxBits;
    int size = (1 << logsize);


    //int decomp_size = newcontext_->first_context_data()->total_coeff_modulus_bit_count() / pir_params_.gsw_base;
    int decomp_size = pir_params_.gsw_decomp_size ;
    int sk_decomp_size = newcontext_->first_context_data()->total_coeff_modulus_bit_count() / pir_params_.secret_base;
    CtMuxBits.resize((1 << logsize), GSWCiphertext(2 * decomp_size));
    vector<GSWCiphertext>::iterator gswCiphers_ptr = CtMuxBits.begin();


    thread_server_expand(gswCiphers_ptr, query[1], newcontext_, 0, decomp_size, size, galoisKeys_,  decomp_size, pir_params_.gsw_base, sk_decomp_size, pir_params_.secret_base, sk_enc_);

    for (uint32_t jj = 0; jj < CtMuxBits.size(); jj++)
    {
        poc_nfllib_ntt_gsw(CtMuxBits[jj],newcontext_);
    }

    auto expand_start = std::chrono::high_resolution_clock::now();
    //for remaining dimensions we treat them differently
    uint64_t  previous_dim=0;
    for (uint32_t i = 1; i < nvec.size(); i++){

        uint64_t n_i = nvec[i];

        product /= n_i;
        vector<Ciphertext> intermediateCtxts(product);//output size of this dimension




        for (uint64_t k = 0; k < product; k++) {


            intermediateCtxts[k].resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
            vector<uint64_t *> rlwe_decom;
            rwle_decompositions(first_dim_intermediate_cts[k], newcontext_, decomp_size, pir_params_.gsw_base, rlwe_decom);
            poc_nfllib_ntt_rlwe_decomp(rlwe_decom);
            poc_nfllib_external_product(CtMuxBits[0 + previous_dim], rlwe_decom, newcontext_, decomp_size, intermediateCtxts[k],1);
            for (auto p : rlwe_decom) {
                free(p);
            }

            for (uint64_t j = 1; j < n_i; j++) {


                Ciphertext temp;
                rlwe_decom.clear();
                rwle_decompositions(first_dim_intermediate_cts[k + j * product], newcontext_, decomp_size, pir_params_.gsw_base, rlwe_decom);
                poc_nfllib_ntt_rlwe_decomp(rlwe_decom);
                temp.resize(newcontext_, newcontext_->first_context_data()->parms_id(), 2);
                poc_nfllib_external_product(CtMuxBits[j + previous_dim], rlwe_decom, newcontext_, decomp_size, temp,1);

                for (auto p : rlwe_decom) {
                    free(p);
                }
                evaluator_->add_inplace(intermediateCtxts[k], temp); // Adds to first component.



            }

        }



        for (uint32_t jj = 0; jj < intermediateCtxts.size(); jj++) {

            poc_nfllib_intt_ct(intermediateCtxts[jj],newcontext_);

        }

        first_dim_intermediate_cts.clear();
        first_dim_intermediate_cts=intermediateCtxts;
        previous_dim=previous_dim+n_i;

    }


    auto expand_end  = high_resolution_clock::now();
    int durrr =  duration_cast<milliseconds>(expand_end - expand_start).count();
    cout << "remaining-dimensions cost" << durrr  << endl;


    auto Total_end  = high_resolution_clock::now();
    durrr =  duration_cast<milliseconds>(Total_end - expand_start).count();
    cout << "remaining-dimensions cost" << durrr  << endl;

    return first_dim_intermediate_cts;
}