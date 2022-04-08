#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <seal/seal.h>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

  uint64_t number_of_items = 2048;
  uint64_t size_per_item = 288; // in bytes
  uint32_t N = 8192;

  // Recommended values: (logt, d) = (12, 2) or (8, 1).
  uint32_t logt = 20;

  EncryptionParameters enc_params(scheme_type::bfv);

  // Generates all parameters

  cout << "Main: Generating SEAL parameters" << endl;
  gen_encryption_params(N, logt, enc_params);

  cout << "Main: Verifying SEAL parameters" << endl;
  verify_encryption_params(enc_params);
  cout << "Main: SEAL parameters are good" << endl;

  SEALContext context(enc_params, true);
  KeyGenerator keygen(context);

  SecretKey secret_key = keygen.secret_key();
  Encryptor encryptor(context, secret_key);
  Decryptor decryptor(context, secret_key);
  Evaluator evaluator(context);
  BatchEncoder encoder(context);
  logt = floor(log2(enc_params.plain_modulus().value()));

  uint32_t plain_modulus = enc_params.plain_modulus().value();

  size_t slot_count = encoder.slot_count();

  vector<uint64_t> coefficients(slot_count, 0ULL);
  for (uint32_t i = 0; i < coefficients.size(); i++) {
    coefficients[i] = rand() % plain_modulus;
  }
  Plaintext pt;
  encoder.encode(coefficients, pt);
  Ciphertext ct;
  encryptor.encrypt_symmetric(pt, ct);
  std::cout << "Encrypting" << std::endl;
  auto context_data = context.last_context_data();
  auto parms_id = context.last_parms_id();

  evaluator.mod_switch_to_inplace(ct, parms_id);

  EncryptionParameters params = context_data->parms();
  std::cout << "Encoding" << std::endl;
  vector<Plaintext> encoded = decompose_to_plaintexts(params, ct);
  std::cout << "Expansion Factor: " << encoded.size() << std::endl;
  std::cout << "Decoding" << std::endl;
  Ciphertext decoded(context, parms_id);
  compose_to_ciphertext(params, encoded, decoded);
  std::cout << "Checking" << std::endl;
  Plaintext pt2;
  decryptor.decrypt(decoded, pt2);

  assert(pt == pt2);

  std::cout << "Worked" << std::endl;

  return 0;
}
