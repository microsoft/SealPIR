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

int query_test(uint64_t num_items, uint64_t item_size, uint32_t degree,
               uint32_t lt, uint32_t dim);

int main(int argc, char *argv[]) {
  // Quick check
  assert(query_test(1 << 10, 288, 4096, 20, 1) == 0);

  assert(query_test(1 << 10, 288, 4096, 20, 2) == 0);

  assert(query_test(1 << 10, 288, 4096, 20, 3) == 0);

  assert(query_test(1 << 10, 288, 8192, 20, 2) == 0);

  // Forces ciphertext expansion to be the same as the degree
  assert(query_test(1 << 20, 288, 4096, 20, 1) == 0);

  assert(query_test(1 << 20, 288, 4096, 20, 2) == 0);
}

int query_test(uint64_t num_items, uint64_t item_size, uint32_t degree,
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

  random_device rd;
  for (uint64_t i = 0; i < number_of_items; i++) {
    for (uint64_t j = 0; j < size_per_item; j++) {
      uint8_t val = rd() % 256;
      db.get()[(i * size_per_item) + j] = val;
      db_copy.get()[(i * size_per_item) + j] = val;
    }
  }

  // Initialize PIR Server
  cout << "Main: Initializing server and client" << endl;
  PIRServer server(enc_params, pir_params);

  // Initialize PIR client....
  PIRClient client(enc_params, pir_params);
  GaloisKeys galois_keys = client.generate_galois_keys();

  // Set galois key for client with id 0
  cout << "Main: Setting Galois keys...";
  server.set_galois_key(0, galois_keys);

  // Measure database setup
  auto time_pre_s = high_resolution_clock::now();
  server.set_database(move(db), number_of_items, size_per_item);
  server.preprocess_database();
  cout << "Main: database pre processed " << endl;
  auto time_pre_e = high_resolution_clock::now();
  auto time_pre_us =
      duration_cast<microseconds>(time_pre_e - time_pre_s).count();

  // Choose an index of an element in the DB
  uint64_t ele_index =
      rd() % number_of_items; // element in DB at random position
  uint64_t index = client.get_fv_index(ele_index);   // index of FV plaintext
  uint64_t offset = client.get_fv_offset(ele_index); // offset in FV plaintext
  cout << "Main: element index = " << ele_index << " from [0, "
       << number_of_items - 1 << "]" << endl;
  cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

  // Measure query generation
  auto time_query_s = high_resolution_clock::now();
  PirQuery query = client.generate_query(index);
  auto time_query_e = high_resolution_clock::now();
  auto time_query_us =
      duration_cast<microseconds>(time_query_e - time_query_s).count();
  cout << "Main: query generated" << endl;

  // To marshall query to send over the network, you can use
  // serialize/deserialize: std::string query_ser = serialize_query(query);
  // PirQuery query2 = deserialize_query(d, 1, query_ser, CIPHER_SIZE);

  // Measure query processing (including expansion)
  auto time_server_s = high_resolution_clock::now();
  PirReply reply = server.generate_reply(query, 0);
  auto time_server_e = high_resolution_clock::now();
  auto time_server_us =
      duration_cast<microseconds>(time_server_e - time_server_s).count();

  // Measure response extraction
  auto time_decode_s = chrono::high_resolution_clock::now();
  vector<uint8_t> elems = client.decode_reply(reply, offset);
  auto time_decode_e = chrono::high_resolution_clock::now();
  auto time_decode_us =
      duration_cast<microseconds>(time_decode_e - time_decode_s).count();

  assert(elems.size() == size_per_item);

  bool failed = false;
  // Check that we retrieved the correct element
  for (uint32_t i = 0; i < size_per_item; i++) {
    if (elems[i] != db_copy.get()[(ele_index * size_per_item) + i]) {
      cout << "Main: elems " << (int)elems[i] << ", db "
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
  cout << "Main: PIRClient query generation time: " << time_query_us / 1000
       << " ms" << endl;
  cout << "Main: PIRServer reply generation time: " << time_server_us / 1000
       << " ms" << endl;
  cout << "Main: PIRClient answer decode time: " << time_decode_us / 1000
       << " ms" << endl;
  cout << "Main: Reply num ciphertexts: " << reply.size() << endl;

  return 0;
}
