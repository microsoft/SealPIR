#include "pir.hpp"
#include <time.h>
#define BILLION 1000000000L
#define MILLION (1.0*1000000L)
#define KILO (1.0*1024L)
#include <fstream>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <random>

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60
#define NUM_SLOT 64
#define NUM_THREAD 2


int main(int argc, char *argv[]) {

  uint64_t number_of_items = 1 << 22;
  uint64_t size_per_item = 288 << 3; // 288 B. 


  int n = 2048;
  int logt = 21;
  uint64_t plainMod = static_cast<uint64_t> (1) << logt;
  double hao_const =  0.5 * log2(number_of_items *size_per_item) - 0.5 * log2(n);

  int logtprime = logt; 
  while(true){
    if (logtprime + ceil(hao_const - 0.5*log2(logtprime)) == logt) break;
    logtprime--; 
  }

  int number_of_plaintexts = ceil (((double)(number_of_items)* size_per_item / n) / logtprime );

  EncryptionParameters parms;
  parms.set_poly_modulus("1x^" + std::to_string(n) + " + 1");
  vector<SmallModulus> coeff_mod_array;
  int logq = 0;

  for (int i = 0; i < 1; ++i)
  {
    coeff_mod_array.emplace_back(SmallModulus());
    coeff_mod_array[i] = small_mods_60bit(i);
    logq += coeff_mod_array[i].bit_count();
  }

  parms.set_coeff_modulus(coeff_mod_array);
  parms.set_plain_modulus(plainMod);

  pirParams pirparms;

  uint64_t newplainMod = 1 << logtprime;


  int item_per_plaintext = floor((double)get_power_of_two(newplainMod) *n / size_per_item);


  pirparms.d = 2;
  pirparms.alpha = 1;
  pirparms.dbc = 8;
  pirparms.N = number_of_plaintexts;

  int sqrt_items = ceil(sqrt(number_of_plaintexts));
  int bound1 = ceil((double) number_of_plaintexts / sqrt_items);
  int bound2 = sqrt_items;

  vector<int> Nvec = { bound1, bound2 };
  pirparms.Nvec = Nvec;


  // Initialize PIR client....
  PIRClient client(parms, pirparms);

  GaloisKeys galois_keys = client.generate_galois_keys();


  EncryptionParameters newparms = client.get_new_parms();
  galois_keys.mutable_hash_block() = newparms.hash_block();
  PIRServer server(client.get_new_parms(), client.get_pir_parms());

  server.set_galois_key(0, galois_keys);

  int index = 3; // we want to obtain the 3rd item. 


  random_device rd;

  vector<uint64_t> no_choose(n+1);
  vector<uint64_t> choose(n+1);


  for (int i = 0; i < n+1; i++) {
    no_choose[i] = rd() % newplainMod;
    choose[i] = rd() % newplainMod;
    if (i == n) {
      choose[i] = 0; 
      no_choose[i] = 0; 
    }
  }

  unique_ptr<uint64_t> items_anchor(new uint64_t[bound1*bound2*(n + 1)]); 
  vector<Plaintext> items;

  uint64_t * items_ptr = items_anchor.get();

  for (int i = 0; i < bound1*bound2; i++) {
    items.emplace_back(n + 1, items_ptr); 
    if (i != index) {
      util::set_uint_uint(no_choose.data(), n+1, items_ptr);
    } else {
      util::set_uint_uint(choose.data(), n+1, items_ptr);
    }
    items_ptr += n + 1; 
  }
  server.set_database(&items);

  auto time_querygen_start = chrono::high_resolution_clock::now();

  pirQuery query = client.generate_query(index);

  for (int i = 0; i < query.size(); i++) {
    query[i].mutable_hash_block() = newparms.hash_block();
  }

  auto time_querygen_end = chrono::high_resolution_clock::now();

  cout << "PIRClient query generation time : " << chrono::duration_cast<chrono::microseconds>(time_querygen_end - time_querygen_start).count() / 1000
    << " ms" << endl;
  cout << "Query size = " << (double) n * 2 * logq * pirparms.d / (1024 * 8) << "KB" << endl;

  auto time_pre_start = chrono::high_resolution_clock::now();

  server.preprocess_database();

  auto time_pre_end = chrono::high_resolution_clock::now();
  cout << "pre-processing time = " << chrono::duration_cast<chrono::microseconds>(time_pre_end - time_pre_start).count() / 1000
    << " ms" << endl;

  pirQuery query_ser = deserialize_ciphertexts(2, serialize_ciphertexts(query), 32828);

  auto time_server_start = chrono::high_resolution_clock::now();

  pirReply reply = server.generate_reply(query_ser, 0);


  auto time_server_end = chrono::high_resolution_clock::now();


  cout << "Server reply generation time : " << chrono::duration_cast<chrono::microseconds>(time_server_end - time_server_start).count() / 1000
    << " ms" << endl;

  cout<<"Reply ciphertexts"<<reply.size()<<endl;


  cout << "Reply size = " << (double) reply.size() * n * 2 * logq  / (1024 * 8) << "KB" << endl;

  auto time_decode_start = chrono::high_resolution_clock::now();

  Plaintext result = client.decode_reply(reply);

  auto time_decode_end = chrono::high_resolution_clock::now();

  cout << "PIRClient decoding time : " << chrono::duration_cast<chrono::microseconds>(time_decode_end - time_decode_start).count() / 1000
    << " ms" << endl;

  cout << "Result = ";
  bool pircorrect = true;
  for (int i = 0; i < n; i++) {
    if (result[i] != choose[i]) {
      pircorrect = false;
      break;
    }
  }
  if (pircorrect) {
    cout << "PIR result correct!!" << endl;
  }
  else {
    cout << "PIR result wrong!" << endl;
  }

  return 0;
}
