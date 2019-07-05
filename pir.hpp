#pragma once

#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include <cassert>
#include <cmath>
#include <string>
#include <vector>

#define CIPHER_SIZE 32841

typedef std::vector<seal::Plaintext> Database;
typedef std::vector<std::vector<seal::Ciphertext>> PirQuery;
typedef std::vector<seal::Ciphertext> PirReply;

struct PirParams {
    std::uint64_t n;                 // number of plaintexts in database
    std::uint32_t d;                 // number of dimensions for the database (1 or 2)
    std::uint32_t expansion_ratio;   // ratio of ciphertext to plaintext
    std::uint32_t dbc;               // decomposition bit count (used by relinearization)
    std::vector<std::uint64_t> nvec; // size of each of the d dimensions
};

void gen_params(std::uint64_t ele_num,  // number of elements (not FV plaintexts) in database
                std::uint64_t ele_size, // size of each element
                std::uint32_t N,        // degree of polynomial
                std::uint32_t logt,     // bits of plaintext coefficient
                std::uint32_t d,        // dimension of database
                seal::EncryptionParameters &params,
                PirParams &pir_params);

// returns the plaintext modulus after expansion
std::uint32_t plainmod_after_expansion(std::uint32_t logt, std::uint32_t N, 
                                       std::uint32_t d, std::uint64_t ele_num,
                                       std::uint64_t ele_size);

// returns the number of plaintexts that the database can hold
std::uint64_t plaintexts_per_db(std::uint32_t logtp, std::uint64_t N, std::uint64_t ele_num,
                                std::uint64_t ele_size);

// returns the number of elements that a single FV plaintext can hold
std::uint64_t elements_per_ptxt(std::uint32_t logtp, std::uint64_t N, std::uint64_t ele_size);

// returns the number of coefficients needed to store one element
std::uint64_t coefficients_per_element(std::uint32_t logtp, std::uint64_t ele_size);

// Converts an array of bytes to a vector of coefficients, each of which is less
// than the plaintext modulus
std::vector<std::uint64_t> bytes_to_coeffs(std::uint32_t limit, const std::uint8_t *bytes,
                                           std::uint64_t size);

// Converts an array of coefficients into an array of bytes
void coeffs_to_bytes(std::uint32_t logtp, const seal::Plaintext &coeffs, std::uint8_t *output,
                     std::uint32_t size_out);

// Takes a vector of coefficients and returns the corresponding FV plaintext
void vector_to_plaintext(const std::vector<std::uint64_t> &coeffs, seal::Plaintext &plain);

// Since the database has d dimensions, and an item is a particular cell
// in the d-dimensional hypercube, this function computes the corresponding
// index for each of the d dimensions
std::vector<std::uint64_t> compute_indices(std::uint64_t desiredIndex,
                                           std::vector<std::uint64_t> nvec);

// Serialize and deserialize ciphertexts to send them over the network
PirQuery deserialize_query(std::uint32_t d, uint32_t count, std::string s, std::uint32_t len_ciphertext);
std::vector<seal::Ciphertext> deserialize_ciphertexts(std::uint32_t count, std::string s,
                                                      std::uint32_t len_ciphertext);
std::string serialize_ciphertexts(std::vector<seal::Ciphertext> c);
std::string serialize_query(std::vector<std::vector<seal::Ciphertext>> c);

// Serialize and deserialize galois keys to send them over the network
std::string serialize_galoiskeys(seal::GaloisKeys g);
seal::GaloisKeys *deserialize_galoiskeys(std::string s);
