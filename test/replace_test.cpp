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

int replace_test(uint64_t num_items, uint64_t item_size, uint32_t degree,
                 uint32_t lt, uint32_t dim);

int main(int argc, char *argv[]) {
  // Quick check
  assert(replace_test(1 << 13, 1, 4096, 20, 1) == 0);

  // Forces ciphertext expansion to be the same as the degree
  assert(replace_test(1 << 20, 288, 4096, 20, 1) == 0);

  assert(replace_test(1 << 20, 288, 4096, 20, 2) == 0);
}

int replace_test(uint64_t num_items, uint64_t item_size, uint32_t degree,
                 uint32_t lt, uint32_t dim) {
  uint64_t number_of_items = num_items;
  uint64_t size_per_item = item_size; // in bytes
  uint32_t N = degree;

  // Recommended values: (logt, d) = (12, 2) or (8, 1).
  uint32_t logt = lt;
  uint32_t d = dim;

  EncryptionParameters enc_params(scheme_type::bfv);
  PirParams pir_params;

  // Generates all parameters

  cout << "Main: Generating SEAL parameters" << endl;
  gen_encryption_params(N, logt, enc_params);

  cout << "Main: Verifying SEAL parameters" << endl;
  verify_encryption_params(enc_params);
  cout << "Main: SEAL parameters are good" << endl;

  cout << "Main: Generating PIR parameters" << endl;
  gen_pir_params(number_of_items, size_per_item, d, enc_params, pir_params);

  // gen_params(number_of_items, size_per_item, N, logt, d, enc_params,
  // pir_params);
  print_pir_params(pir_params);

  cout << "Main: Initializing the database (this may take some time) ..."
       << endl;

  // Create test database
  auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

  // Copy of the database. We use this at the end to make sure we retrieved
  // the correct element.
  auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

  seal::Blake2xbPRNGFactory factory;
  auto gen =  factory.create();

  for (uint64_t i = 0; i < number_of_items; i++) {
    for (uint64_t j = 0; j < size_per_item; j++) {
      uint8_t val = gen->generate() % 256;
      db.get()[(i * size_per_item) + j] = val;
      db_copy.get()[(i * size_per_item) + j] = val;
    }
  }

  // Initialize PIR Server
  cout << "Main: Initializing server and client" << endl;
  PIRServer server(enc_params, pir_params);

  // Initialize PIR client....
  PIRClient client(enc_params, pir_params);
  Ciphertext one_ct = client.get_one();
  GaloisKeys galois_keys = client.generate_galois_keys();

  // Set galois key for client with id 0
  cout << "Main: Setting Galois keys...";
  server.set_galois_key(0, galois_keys);

  // Measure database setup
  auto time_pre_s = high_resolution_clock::now();
  server.set_database(move(db), number_of_items, size_per_item);
  server.preprocess_database();
  server.set_one_ct(one_ct);
  cout << "Main: database pre processed " << endl;
  auto time_pre_e = high_resolution_clock::now();
  auto time_pre_us =
      duration_cast<microseconds>(time_pre_e - time_pre_s).count();


  // Choose an index of an element in the DB
  random_device rd;
  uint64_t ele_index =
      rd() % number_of_items; // element in DB at random position
  uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext
  cout << "Main: element index = " << ele_index << " from [0, "
       << number_of_items - 1 << "]" << endl;
  cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

  // Generate a new element
  vector<uint8_t> new_element(size_per_item);
  vector<uint8_t> new_element_copy(size_per_item);
  for (uint64_t i = 0; i < size_per_item; i++) {
    uint8_t val = rd() % 256;
    new_element[i] = val;
    new_element_copy[i] = val;
  }

  // Get element to replace
  auto time_server_s = high_resolution_clock::now();
  Ciphertext reply = server.simple_query(index);
  auto time_server_e = high_resolution_clock::now();
  auto time_server_us =
      duration_cast<microseconds>(time_server_e - time_server_s).count();
  auto time_decode_s = chrono::high_resolution_clock::now();
  Plaintext old_pt = client.decrypt(reply);
  auto time_decode_e = chrono::high_resolution_clock::now();
  auto time_decode_us =
      duration_cast<microseconds>(time_decode_e - time_decode_s).count();

  // Replace element
  Modulus t = enc_params.plain_modulus();
  logt = floor(log2(t.value()));
  vector<uint64_t> new_coeffs =
      bytes_to_coeffs(logt, new_element.data(), size_per_item);
  Plaintext new_pt = client.replace_element(old_pt, new_coeffs, offset);
  server.simple_set(index, new_pt);

  // Get the replaced element
  PirQuery query = client.generate_query(index);
  PirReply server_reply = server.generate_reply(query, 0);
  vector<uint8_t> elems = client.decode_reply(server_reply, offset);
  // vector<uint8_t> elems =
  // client.extract_bytes(client.decrypt(server.simple_query(index)), offset);
  vector<uint8_t> old_elems = client.extract_bytes(old_pt, offset);

  assert(elems.size() == size_per_item);

  bool failed = false;
  // Check that we retrieved the correct element
  for (uint32_t i = 0; i < size_per_item; i++) {
    if (elems[i] != new_element_copy[i]) {
      cout << "Main: elems " << (int)elems[i] << ", new "
           << (int)new_element_copy[i] << ", old "
           << (int)db_copy.get()[(ele_index * size_per_item) + i] << endl;
      cout << "Main: PIR result wrong at " << i << endl;
      failed = true;
    }
  }
  if (failed) {
    return -1;
  }

  // Output results
  cout << "Main: PIR result correct!" << endl;
  cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms"
       << endl;
  cout << "Main: PIRServer reply generation time: " << time_server_us / 1000
       << " ms" << endl;
  cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000
       << " ms" << endl;

  return 0;
}
