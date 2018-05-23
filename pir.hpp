#ifndef SEAL_PIR_H
#define SEAL_PIR_H

#include <iostream>
#include <iomanip>
#include <math.h>
#include <chrono>
#include "seal/memorypoolhandle.h"
#include "seal/encryptor.h"
#include "seal/decryptor.h"
#include "seal/encryptionparams.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/evaluationkeys.h"
#include "seal/galoiskeys.h"
#include "seal/seal.h"
#include "math.h"
#include "seal/util/polyarith.h"
#include "seal/util/uintarith.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal;
using namespace seal::util;
typedef std::vector<Plaintext> dataBase;
typedef std::vector<Ciphertext> pirQuery;
typedef std::vector<Ciphertext> pirReply;

vector<Ciphertext> deserialize_ciphertexts(int count, string s, int len_ciphertext);
string serialize_ciphertexts(vector<Ciphertext> c);
string serialize_plaintext(Plaintext p);
string serialize_plaintexts(vector<Plaintext> p); 

struct pirParams {
  int N;
  int size;
  int alpha; 
  int d; 
  vector<int> Nvec;
  int expansion_ratio_;
  int dbc;
};

void vector_to_plaintext(const std::vector<std::uint64_t> &coeffs, Plaintext &plain); 


vector<int> compute_indices(int desiredIndex, vector<int> Nvec); 

class PIRClient {
  public:
    PIRClient(const seal::EncryptionParameters & parms, pirParams & pirparms);
    pirQuery generate_query(int desiredIndex);
    Plaintext decode_reply(pirReply reply);

    GaloisKeys generate_galois_keys();

    void print_info(Ciphertext &encrypted);

    EncryptionParameters get_new_parms() {
      return newparms_;
    }

    pirParams get_pir_parms() {
      return pirparms_;
    }

    Ciphertext compose_to_ciphertext(vector<Plaintext> plains);


  private:
    EncryptionParameters parms_;
    EncryptionParameters newparms_;

    pirParams pirparms_;
    unique_ptr<Encryptor> encryptor_;
    unique_ptr<Decryptor> decryptor_;
    unique_ptr<Evaluator> evaluator_;
    unique_ptr<KeyGenerator> keygen_;
};

class PIRServer
{
  public: 
    PIRServer(const seal::EncryptionParameters &parms, const pirParams &pirparams);

    // Reads the database from file.
    void read_database_from_file(string file); 

    // Preprocess the databse 
    void preprocess_database();

    void set_database(vector<Plaintext> *db);

    pirReply generate_reply(pirQuery query, int client_id);
    vector<Ciphertext> expand_query(const Ciphertext & encrypted, int d, const GaloisKeys &galkey);

    void set_galois_key(int client_id, GaloisKeys galkey) {
      galoisKeys_[client_id] = galkey;
    }

    void multiply_power_of_X(const Ciphertext &encrypted, Ciphertext & destination, int index);

    void decompose_to_plaintexts_ptr(const Ciphertext & encrypted, uint64_t* plain_ptr);

    vector<Plaintext> decompose_to_plaintexts(const Ciphertext &encrypted);

  private:
    EncryptionParameters parms_;
    pirParams pirparams_;
    map<int, GaloisKeys> galoisKeys_;
    dataBase *dataBase_ = nullptr;
    unique_ptr<Evaluator> evaluator_;
    bool is_db_preprocessed_;
};

extern "C" {
  void cpp_buffer_free(char* buf);

  // client-specific methods
  void* cpp_client_setup(uint64_t len_db_total_bytes, uint64_t num_db_entries);
  char* cpp_client_generate_galois_keys(void *pir); 
  char* cpp_client_generate_query(void* pir, uint64_t chosen_idx, uint64_t* rlen_query_total_bytes, uint64_t* rnum_query_slots);
  char* cpp_client_process_reply(void* pir, char* r, uint64_t len_response_total_bytes, uint64_t num_response_slots, uint64_t* rlen_answer_total_bytes);
  void cpp_client_update_db_params(void* pir, uint64_t len_db_total_bytes, uint64_t num_db_entries, uint64_t alpha, uint64_t d);
  void cpp_client_free(void* pir);

  // server-specific methods
  void* cpp_server_setup(uint64_t len_db_total_bytes, char *db, uint64_t num_db_entries); 
  char* cpp_server_process_query(void* pir, char* q, uint64_t len_query_total_bytes, uint64_t num_query_slots, uint64_t* rlen_response_total_bytes, uint64_t* rnum_response_slots);
  void cpp_server_set_galois_keys(void *pir, char *q, uint64_t len_total_bytes, int client_id);
  void cpp_server_free(void* pir);
}
#endif
