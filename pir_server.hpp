#pragma once

#include "pir.hpp"
#include <map>
#include <memory>
#include <vector>

class PIRServer {
  public:
    PIRServer(const seal::EncryptionParameters &expanded_params, const PirParams &pir_params);
    ~PIRServer();

    void update_parameters(const seal::EncryptionParameters &expanded_params,
                           const PirParams &pir_params);

    // NOTE: server takes over ownership of db and frees it when it exits.
    // Caller cannot free db
    void set_database(std::vector<seal::Plaintext> *db);
    void set_database(const std::uint8_t *bytes, std::uint64_t ele_num, std::uint64_t ele_size);
    void preprocess_database();

    std::vector<seal::Ciphertext> expand_query(const seal::Ciphertext &encrypted, std::uint32_t m,
                                               uint32_t client_id);

    PirReply generate_reply(PirQuery query, std::uint32_t client_id);

    void set_galois_key(std::uint32_t client_id, seal::GaloisKeys galkey);

  private:
    seal::EncryptionParameters expanded_params_; // SEAL parameters
    PirParams pir_params_;                       // PIR parameters
    Database *db_ = nullptr;
    bool is_db_preprocessed_;
    std::map<int, seal::GaloisKeys> galoisKeys_;
    std::unique_ptr<seal::Evaluator> evaluator_;

    void decompose_to_plaintexts_ptr(const seal::Ciphertext &encrypted, std::uint64_t *plain_ptr);
    std::vector<seal::Plaintext> decompose_to_plaintexts(const seal::Ciphertext &encrypted);
    void multiply_power_of_X(const seal::Ciphertext &encrypted, seal::Ciphertext &destination,
                             std::uint32_t index);
};
