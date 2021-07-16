#pragma once

#include "pir.hpp"
#include <map>
#include <memory>
#include <vector>
#include "pir_client.hpp"

class PIRServer {
  public:
    PIRServer(const seal::EncryptionParameters &enc_params, const PirParams &pir_params);

    // NOTE: server takes over ownership of db and frees it when it exits.
    // Caller cannot free db
    void set_database(std::unique_ptr<std::vector<seal::Plaintext>> &&db);
    void set_database(const std::unique_ptr<const std::uint8_t[]> &bytes, std::uint64_t ele_num, std::uint64_t ele_size);
    void preprocess_database();

    std::vector<seal::Ciphertext> expand_query(
            const seal::Ciphertext &encrypted, std::uint32_t m, std::uint32_t client_id);

    PirQuery deserialize_query(std::stringstream &stream);
    PirReply generate_reply(PirQuery &query, std::uint32_t client_id);
    // Serializes the reply into the provided stream and returns the number of bytes written
    int serialize_reply(PirReply &reply, std::stringstream &stream);

    void set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey);

    seal::Ciphertext simple_query(std::uint64_t index);
    //This is only used for simple_query
    void set_one_ct(seal::Ciphertext one);

  private:
    seal::EncryptionParameters enc_params_; // SEAL parameters
    PirParams pir_params_;              // PIR parameters
    std::unique_ptr<Database> db_;
    bool is_db_preprocessed_;
    std::map<int, seal::GaloisKeys> galoisKeys_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::shared_ptr<seal::SEALContext> context_;

    //This is only uesd for simple_query
    seal::Ciphertext one_;

    void decompose_to_plaintexts_ptr(const seal::Ciphertext &encrypted, seal::Plaintext *plain_ptr, int logt);
    std::vector<seal::Plaintext> decompose_to_plaintexts(const seal::Ciphertext &encrypted);
    void multiply_power_of_X(const seal::Ciphertext &encrypted, seal::Ciphertext &destination,
                             std::uint32_t index);
};
