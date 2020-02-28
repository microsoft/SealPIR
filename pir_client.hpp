#pragma once

#include "pir.hpp"
#include <memory>
#include <vector>

using namespace std; 

class PIRClient {
  public:
    PIRClient(const seal::EncryptionParameters &parms,
               const PirParams &pirparms);

    PirQuery generate_query(std::uint64_t desiredIndex);
    seal::Plaintext decode_reply(PirReply reply);

    seal::GaloisKeys generate_galois_keys();

    // Index and offset of an element in an FV plaintext
    uint64_t get_fv_index(uint64_t element_idx, uint64_t ele_size);
    uint64_t get_fv_offset(uint64_t element_idx, uint64_t ele_size);

    void compute_inverse_scales(); 

  private:
    seal::EncryptionParameters params_;
    PirParams pir_params_;

    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::KeyGenerator> keygen_;
    std::shared_ptr<seal::SEALContext> newcontext_;

    vector<uint64_t> indices_; // the indices for retrieval. 
    vector<uint64_t> inverse_scales_; 

    seal::Ciphertext compose_to_ciphertext(std::vector<seal::Plaintext> plains);

    friend class PIRServer;
};
