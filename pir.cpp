#include "pir.hpp"
using namespace std;
#include <vector>
using namespace seal;
using namespace seal::util;

PIRClient::PIRClient(const seal::EncryptionParameters &parms, pirParams & pirparms) {
  parms_ = parms; 
  SEALContext context(parms);
  keygen_.reset(new KeyGenerator(context));

  encryptor_.reset(new Encryptor(context, keygen_->public_key()));

  uint64_t plainMod = parms.plain_modulus().value();

  int N = pirparms.Nvec[0];
  int logN = ceil(log(N) / log(2)); 

  EncryptionParameters newparms = parms;
  newparms.set_plain_modulus(plainMod >> logN); 
  newparms_ = newparms;
  SEALContext newcontext(newparms);
  SecretKey secret_key = keygen_->secret_key();
  secret_key.mutable_hash_block() = newparms.hash_block();
  decryptor_.reset(new Decryptor(newcontext, secret_key));
  evaluator_.reset(new Evaluator(newcontext));

  int expansion_ratio = 0;
  for (int i = 0; i < parms.coeff_modulus().size(); ++i)
  {
    double logqi = log(parms.coeff_modulus()[i].value());
    expansion_ratio += ceil(logqi / log(newparms.plain_modulus().value()));
  }
  pirparms.expansion_ratio_ = expansion_ratio << 1;
  pirparms_ = pirparms;
}

pirQuery PIRClient::generate_query(int desiredIndex) { 
  vector<int> indices = compute_indices(desiredIndex, pirparms_.Nvec); 
  vector<Ciphertext> result;
  for (int i = 0; i < indices.size(); i++) {
    Ciphertext dest;
    encryptor_->encrypt(Plaintext("1x^" + std::to_string(indices[i])), dest);
    result.push_back(dest); 
  }
  return result;
}

Plaintext PIRClient::decode_reply(pirReply reply) {
  int exp_ratio = pirparms_.expansion_ratio_;
  vector<Ciphertext> temp = reply;
  int recursion_level = pirparms_.d;
  for (int i = 0; i < recursion_level; i++) {
    vector<Ciphertext> newtemp;
    vector<Plaintext> tempplain;
    for (int j = 0; j < temp.size(); j++) {
      Plaintext ptxt;
      decryptor_->decrypt(temp[j], ptxt);
      tempplain.push_back(ptxt);  
      if ( (j + 1) % exp_ratio == 0 && j > 0) {
        // Combine into one ciphertext. 
        Ciphertext combined = compose_to_ciphertext(tempplain); 
        newtemp.push_back(combined);
      }
    }	
    if (i == recursion_level - 1) {
      if (temp.size() != 1) throw;
      return tempplain[0];
    }
    else {
      tempplain.clear();
      temp = newtemp;
    }
  }

}

GaloisKeys PIRClient::generate_galois_keys() {
  vector<uint64_t> galois_elts;
  int n = parms_.poly_modulus().coeff_count() - 1;
  int logn = get_power_of_two(n);

  for (int i = 0; i < logn; i++)
  {
    galois_elts.push_back((n + exponentiate_uint64(2, i)) / exponentiate_uint64(2, i));
  }

  GaloisKeys galois_keys;
  keygen_->generate_galois_keys(pirparms_.dbc, galois_elts, galois_keys);
  return galois_keys;
}

void PIRClient::print_info(Ciphertext & encrypted)
{
  Plaintext ptxt;
  decryptor_->decrypt(encrypted, ptxt);
}

// Given a vector N1, ..., Nd and a number desired index j between 0 and prod(N_i). 
// Return j indices j1, ..., jd such that  j = j1 (N/N1) + j2 (N/N1N2) + ..... 
vector<int> compute_indices(int desiredIndex, vector<int> Nvec) {
  int d = Nvec.size();
  int product = 1;
  for (int i = 0; i < Nvec.size(); i++) {
    product *= Nvec[i];
  }

  int j = desiredIndex;
  vector<int> result;
  for (int i = 0; i < d; i++) {
    product /= Nvec[i]; 
    int ji = j / product; 
    result.push_back(ji); 
    j -= ji*product; 
  }
  return result;
}

PIRServer::PIRServer(const seal::EncryptionParameters & parms, const pirParams &pirparams) {
  parms_ = parms;
  pirparams_ = pirparams;
  SEALContext context(parms);
  evaluator_.reset(new Evaluator(context));
  is_db_preprocessed_ = false;
}

void PIRServer::preprocess_database() {
  if (!is_db_preprocessed_) {
    for (int i = 0; i < dataBase_->size(); i++) {
      evaluator_->transform_to_ntt(dataBase_->operator[](i));
    }
    is_db_preprocessed_ = true;
  }
}

void PIRServer::set_database(vector<Plaintext> *db) {
  if (db == nullptr) {
    throw invalid_argument("db cannot be null");
  }
  dataBase_ = db;
}

pirReply PIRServer::generate_reply(pirQuery query, int client_id) {
  vector<int> Nvec = pirparams_.Nvec;
  uint64_t product = 1; 
  for (int i = 0; i < Nvec.size(); i++) {
    product *= Nvec[i]; 
  }
  int coeff_count = parms_.poly_modulus().coeff_count(); 

  vector<Plaintext> *cur = dataBase_;
  vector<Plaintext> intermediate_plain; // decompose.... 

  auto my_pool = MemoryPoolHandle::New();


  for (int i = 0; i < Nvec.size(); i++) {
    int Ni = Nvec[i];
    vector<Ciphertext> expanded_query = expand_query(query[i], Ni, galoisKeys_[client_id]);
#ifdef DEBUG
    cout << "query ciphertext check: " << endl;
    for (int tt = 0; tt < expanded_query.size(); tt++) {
      client.print_info(expanded_query[tt]);
    }
#endif

    // Transform expanded query to NTT, and ... 
    for (int jj = 0; jj < expanded_query.size(); jj++) {
      evaluator_->transform_to_ntt(expanded_query[jj]);
    }

    // Transform plaintext to NTT. If database is pre-processed, can skip
    if ((!is_db_preprocessed_) || i > 0) {
      for (int jj = 0; jj < cur->size(); jj++) {
        evaluator_->transform_to_ntt((*cur)[jj]);
      }
    }

    product /= Ni;
    vector<Ciphertext> intermediate(product);
    Ciphertext temp1;

    for (int k = 0; k < product; k++) {
      evaluator_->multiply_plain_ntt(expanded_query[0], (*cur)[k], intermediate[k]);
      for (int j = 1; j < Ni; j++) {
        evaluator_->multiply_plain_ntt(expanded_query[j], (*cur)[k + j*product], temp1);
        evaluator_->add(intermediate[k], temp1); // Adds to the first component.
      }
    }
    for (int jj = 0; jj < intermediate.size(); jj++) {
      evaluator_->transform_from_ntt(intermediate[jj]);
    }

#ifdef DEBUG
    cout << "intermediate ciphertext check: " << endl;
    for (int tt = 0; tt < intermediate.size(); tt++) {
      cout << tt + 1 << " / " << intermediate.size() << " ";
      client.print_info(intermediate[tt]);
    }
#endif

    if (i == Nvec.size() - 1) {
      return intermediate;
    } else {
      intermediate_plain.clear();
      intermediate_plain.reserve(pirparams_.expansion_ratio_ * product);
      cur = &intermediate_plain;

      util::Pointer tempplain_ptr(allocate_zero_poly(pirparams_.expansion_ratio_ * product, coeff_count, my_pool));

      for (int rr = 0; rr < product; rr++) {
        decompose_to_plaintexts_ptr(intermediate[rr], tempplain_ptr.get() + rr * pirparams_.expansion_ratio_* coeff_count);
#ifdef DEBUG
        cout << "compose decompose check: " << endl;
        client.print_info(evaluator_->compose_to_ciphertext(tempplain));
#endif              
        for (int jj = 0; jj < pirparams_.expansion_ratio_; jj++){
          int offset = rr * pirparams_.expansion_ratio_* coeff_count + jj * coeff_count;
          intermediate_plain.emplace_back(coeff_count, tempplain_ptr.get() + offset);
        }
      }
      product *= pirparams_.expansion_ratio_; // multiply by expansion rate.
    }
  }
}

vector<Ciphertext> PIRServer::expand_query(const Ciphertext &encrypted, int d, const GaloisKeys &galkey) {

  uint64_t plainMod = parms_.plain_modulus().value();
#ifdef DEBUG
  cout << "PIRServer side plain modulus = " << plainMod << endl;
#endif
  
  // Assume that d is a power of 2. If not, round it to the next power of 2. 
  int logd = ceil(log(d) / log(2));
  Plaintext two("2");
  vector<int> galois_elts;
  int n = parms_.poly_modulus().coeff_count() - 1;
  for (int i = 0; i < logd; i++) {
    galois_elts.push_back((n + exponentiate_uint64(2, i)) / exponentiate_uint64(2, i));
  }
  vector<Ciphertext> temp;
  temp.push_back(encrypted);
  Ciphertext tempctxt;
  Ciphertext tempctxt_rotated;
  Ciphertext tempctxt_shifted;
  Ciphertext tempctxt_rotatedshifted;

  int shift = 1;
  for (int i = 0; i < logd -1; i++) {
    vector<Ciphertext> newtemp(temp.size() << 1);
    int index_raw = (n << 1) - (1 << i);
    int index = (index_raw * galois_elts[i]) % (n << 1);
    for (int a = 0; a < temp.size(); a++) {
      evaluator_->apply_galois(temp[a], galois_elts[i], galkey, tempctxt_rotated); // Can be done in-place
      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);

      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a+temp.size()]); // Enc(2^i x^j) if j = 0 (mod 2**i).
    }
    temp = newtemp;
  }

  // Last iteration of the loop 
  vector<Ciphertext> newtemp(temp.size() << 1);
  int index_raw = (n << 1) - (1 << (logd - 1));
  int index = (index_raw * galois_elts[logd - 1]) % (n << 1);
  for (int a = 0; a < temp.size(); a++) {
    if(a >= (d - (1 << (logd - 1)))) { // corner case. 
      evaluator_->multiply_plain(temp[a], two, newtemp[a]);// plain multiplication by 2.
    }
    else {
      evaluator_->apply_galois(temp[a], galois_elts[logd-1], galkey, tempctxt_rotated); // Can be done in-place
      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);
      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]); // Enc(2^i x^j) if j = 0 (mod 2**i).
    }
  }

  vector<Ciphertext>::const_iterator first = newtemp.begin();
  vector<Ciphertext>::const_iterator last = newtemp.begin() + d;
  vector<Ciphertext> newVec(first, last);
  return newVec;
}


void PIRServer::multiply_power_of_X(const Ciphertext &encrypted, Ciphertext & destination, int index)
{
  // Extract parameter
  int coeff_mod_count = parms_.coeff_modulus().size();
  int coeff_count = parms_.poly_modulus().coeff_count();
  int coeff_bit_count = coeff_mod_count * bits_per_uint64;
  int encrypted_ptr_increment = coeff_count * coeff_mod_count;
  int encrypted_count = encrypted.size();
  
  // First copy over. 
  destination = encrypted;
  
  // Prepare for destination
  // Multiply X^index for each ciphertext polynomial
  for (int i = 0; i < encrypted_count; i++)
  {
    for (int j = 0; j < coeff_mod_count; j++)
    {
      negacyclic_shift_poly_coeffmod(encrypted.pointer(i) + (j * coeff_count), coeff_count - 1, index, parms_.coeff_modulus()[j], destination.mutable_pointer(i) + (j * coeff_count));
    }
  }
}


Ciphertext PIRClient::compose_to_ciphertext(vector<Plaintext> plains) {
  Ciphertext result;
  int encrypted_count = 2;


  int coeff_count = newparms_.poly_modulus().coeff_count();
  int coeff_mod_count = newparms_.coeff_modulus().size();
  int array_poly_uint64_count = coeff_count * coeff_mod_count;

  result.reserve(newparms_, encrypted_count);
  int plain_bit_count = newparms_.plain_modulus().bit_count();
  uint64_t plainMod = newparms_.plain_modulus().value();


  // A triple for loop. Going over polys, moduli, and decomposed index.
  for (int i = 0; i < encrypted_count; i++) {
    uint64_t *encrypted_pointer = result.mutable_pointer(i);
    for (int j = 0; j < coeff_mod_count; j++)
    {
      // populate one poly at a time.
      // create a polynomial to store the current decomposition value which will be copied into the array to populate it at the current index.
      double logqj = log(newparms_.coeff_modulus()[j].value());
      int expansion_ratio = ceil(logqj / log(plainMod));
      uint64_t cur = 1;
      for (int k = 0; k < expansion_ratio; k++)
      {
        // Compose here
        const uint64_t *plain_coeff = plains[k + j*(expansion_ratio)+i*(coeff_mod_count*expansion_ratio)].pointer();
        for (int m = 0; m < coeff_count - 1; m++)
        {
          if (k == 0) {
            *(encrypted_pointer + m + j*coeff_count) = *(plain_coeff + m) * cur;
          }
          else {
            *(encrypted_pointer + m + j*coeff_count) += *(plain_coeff + m) * cur;
          }
        }
        *(encrypted_pointer + coeff_count - 1 + j*coeff_count) = 0;
        cur *= plainMod;
      }

      // Reduction modulo qj. This is needed? 
      for (int m = 0; m < coeff_count; m++)
      {
        *(encrypted_pointer + m + j*coeff_count) %= newparms_.coeff_modulus()[j].value();
      }
    }
  }
  result.mutable_hash_block() = newparms_.hash_block();
  return result;
}


void PIRServer::decompose_to_plaintexts_ptr(const Ciphertext &encrypted, uint64_t* plain_ptr) {
  vector<Plaintext> result;
  int coeff_count = parms_.poly_modulus().coeff_count();
  int coeff_mod_count = parms_.coeff_modulus().size();
  int array_poly_uint64_count = coeff_count * coeff_mod_count;

  int plain_bit_count = parms_.plain_modulus().bit_count();

  int encrypted_count = encrypted.size();

  // Generate powers of t.
  uint64_t plainModMinusOne = parms_.plain_modulus().value() -1;
  int exp = ceil(log2(plainModMinusOne + 1)); 

  for (int i = 0; i < encrypted_count; i++) {
    const uint64_t * encrypted_pointer = encrypted.pointer(i);
    for (int j = 0; j < coeff_mod_count; j++)
    {
      // populate one poly at a time.
      // create a polynomial to store the current decomposition value which will be copied into the array to populate it at the current index.
      int shift = 0;
      int logqj = log2(parms_.coeff_modulus()[j].value());
      int expansion_ratio = (logqj + exp -1) / exp;
      uint64_t curexp = 0;
      for (int k = 0; k < expansion_ratio; k++)
      {
        // Decompose here
        for (int m = 0; m < coeff_count; m++)
        {
          *plain_ptr = (*(encrypted_pointer + m + (j * coeff_count)) >> curexp) & plainModMinusOne;
          plain_ptr++;
        }
        curexp += exp;
      }
    }
  }
  return;
}


std::vector<Plaintext> PIRServer::decompose_to_plaintexts(const Ciphertext &encrypted) {
  vector<Plaintext> result;
  int coeff_count = parms_.poly_modulus().coeff_count();
  int coeff_mod_count = parms_.coeff_modulus().size();
  int array_poly_uint64_count = coeff_count * coeff_mod_count;

  int plain_bit_count = parms_.plain_modulus().bit_count();

  int encrypted_count = encrypted.size();

  // Generate powers of t.
  uint64_t plainMod = parms_.plain_modulus().value();

  for (int i = 0; i < encrypted_count; i++) {
    const uint64_t * encrypted_pointer = encrypted.pointer(i);
    for (int j = 0; j < coeff_mod_count; j++)
    {
      // populate one poly at a time.
      // create a polynomial to store the current decomposition value which will be copied into the array to populate it at the current index.
      int shift = 0;
      int logqj = log(parms_.coeff_modulus()[j].value());
      int expansion_ratio = ceil(logqj / log(plainMod));
      uint64_t cur = 1;
      for (int k = 0; k < expansion_ratio; k++)
      {
        // Decompose here
        BigPoly temp;
        temp.resize(coeff_count, plain_bit_count);
        temp.set_zero();
        uint64_t *plain_coeff = temp.pointer();
        for (int m = 0; m < coeff_count; m++)
        {
          *(plain_coeff + m) = (*(encrypted_pointer + m + (j * coeff_count)) / cur) % plainMod;
        }
        result.push_back(Plaintext(temp));
        cur *= plainMod;
      }
    }
  }
  return result;
}

void vector_to_plaintext(const std::vector<std::uint64_t> &coeffs, Plaintext &plain)
{
  int coeff_count = coeffs.size();
  plain.resize(coeff_count);
util:set_uint_uint(coeffs.data(), coeff_count, plain.pointer());
}


string serialize_ciphertext(Ciphertext c) {
  std::stringstream output(std::ios::binary|std::ios::out);
  c.save(output);
  return output.str();
}

string serialize_ciphertexts(vector<Ciphertext> c) {
  string s;
  for(int i=0; i<c.size(); i++) {
    s.append(serialize_ciphertext(c[i]));
  }
  return s;
}

Ciphertext* deserialize_ciphertext(string s) {
  Ciphertext *c = new Ciphertext();
  std::stringstream input(std::ios::binary|std::ios::in);
  input.str(s);
  c->load(input);
  return c;
}

vector<Ciphertext> deserialize_ciphertexts(int count, string s, int len_ciphertext) {
  vector<Ciphertext> c;
  for(int i=0; i<count; i++) {
    c.push_back(*(deserialize_ciphertext(s.substr(i*len_ciphertext, len_ciphertext))));
  }
  return c;
}

string serialize_plaintext(Plaintext p) {
  std::stringstream output(std::ios::binary|std::ios::out);
  p.save(output);
  return output.str();
}

string serialize_plaintexts(vector<Plaintext> p) {
  string s;
  for(int i=0; i<p.size(); i++) {
    s.append(serialize_plaintext(p[i]));
  }
  return s;
}

Plaintext* deserialize_plaintext(string s) {
  Plaintext *c = new Plaintext();
  std::stringstream input(std::ios::binary|std::ios::in);
  input.str(s);
  c->load(input);
  return c;
}

vector<Plaintext> deserialize_plaintexts(int count, string s, int len_plaintext) {
  vector<Plaintext> p;
  for(int i=0; i<count; i++) {
    p.push_back(*(deserialize_plaintext(s.substr(i*len_plaintext, len_plaintext))));
  }
  return p;
}

string serialize_galoiskeys(GaloisKeys g) {
  std::stringstream output(std::ios::binary|std::ios::out);
  g.save(output);
  return output.str();
}

GaloisKeys* deserialize_galoiskeys(string s) {
  GaloisKeys *g = new GaloisKeys();
  std::stringstream input(std::ios::binary|std::ios::in);
  input.str(s);
  g->load(input);
  return g;
}

void 
cpp_buffer_free(char *buf) {
  free(buf);
}

void* 
cpp_client_setup(uint64_t len_total_bytes, uint64_t num_db_entries) {

  uint64_t number_of_items = num_db_entries;
  uint64_t size_per_item = (len_total_bytes/num_db_entries) << 3;

  int n = 2048;
  int logt = 22;
  uint64_t plainMod = static_cast<uint64_t> (1) << logt;

  int number_of_plaintexts = ceil (((double)(number_of_items)* size_per_item / n) / logt );

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

  int item_per_plaintext = floor((double)get_power_of_two(plainMod) *n / size_per_item);

  pirparms.d = 2;
  pirparms.alpha = 1;
  pirparms.dbc = 8;
  pirparms.N = number_of_plaintexts;
  int sqrt_items = ceil(sqrt(number_of_plaintexts));

  int bound1 = number_of_plaintexts / sqrt_items;
  int bound2 = sqrt_items;

  vector<int> Nvec = { bound1, bound2 };
  pirparms.Nvec = Nvec;

  PIRClient *client = new PIRClient(parms, pirparms);
  return (void*) client;
}

char* 
cpp_client_generate_query(void* pir, uint64_t chosen_idx, uint64_t* rlen_total_bytes, uint64_t* rnum_logical_entries) {

  pirQuery query = ((PIRClient*) pir)->generate_query(chosen_idx);

  string s = serialize_ciphertexts(query);

  *rlen_total_bytes = s.length();
  *rnum_logical_entries = query.size();

  char *outptr, *result; 
  result = (char*)calloc(*rlen_total_bytes, sizeof(char));
  memcpy(result, s.c_str(), s.length());
  return result;
}

char*
cpp_client_generate_galois_keys(void *pir, uint64_t *rlen_total_bytes) {
  GaloisKeys g = ((PIRClient*) pir)->generate_galois_keys();
  string s = serialize_galoiskeys(g); //.c_str();
  char *outptr, *result; 
  result = (char*)calloc(s.length(), sizeof(char));
  memcpy(result, s.c_str(), s.length());
  *rlen_total_bytes = s.length();
  return result;
}

  char*
cpp_client_process_reply(void* pir, char* r, uint64_t len_total_bytes, uint64_t num_logical_entries, uint64_t* rlen_total_bytes)
{
  string s(r);
  vector<Ciphertext> reply = deserialize_ciphertexts(num_logical_entries, s, 32828);
  Plaintext p = ((PIRClient*) pir)->decode_reply(reply);

  string resp = serialize_plaintext(p);
  *rlen_total_bytes = resp.length();
  char *result = (char*)calloc(*rlen_total_bytes, sizeof(char));
  memcpy(result, resp.c_str(), resp.length());
  return result;
}

  void 
cpp_client_free(void *pir)
{
  delete (PIRClient*) pir;
}

  void* 
cpp_server_setup(uint64_t len_total_bytes, char *db, uint64_t num_logical_entries) 
{
  uint64_t max_entry_size_bytes = len_total_bytes/num_logical_entries;
  uint64_t number_of_items = num_logical_entries;
  uint64_t size_per_item = max_entry_size_bytes << 3; // 288 B. 

  int n = 2048;
  int logt = 22;
  uint64_t plainMod = static_cast<uint64_t> (1) << logt;

  int number_of_plaintexts = ceil (((double)(number_of_items)* size_per_item / n) / logt );

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

  int item_per_plaintext = floor((double)get_power_of_two(plainMod) *n / size_per_item);

  pirparms.d = 2;
  pirparms.alpha = 1;

  pirparms.dbc = 8;

  pirparms.N = number_of_plaintexts;

  int sqrt_items = ceil(sqrt(number_of_plaintexts));

  int bound1 = number_of_plaintexts / sqrt_items;
  int bound2 = sqrt_items;

  vector<int> Nvec = { bound1, bound2 };
  pirparms.Nvec = Nvec;

  PIRServer *server = new PIRServer(parms, pirparms);

  string d(db);
  vector<Plaintext> items = deserialize_plaintexts(num_logical_entries, d, max_entry_size_bytes);
  server->set_database(&items);
  server->preprocess_database();
  return (void*) server;
}

  void
cpp_server_set_galois_keys(void *pir, char *q, uint64_t len_total_bytes, int client_id)
{
  string s(q);
  GaloisKeys *g = deserialize_galoiskeys(s);
  ((PIRServer*)pir)->set_galois_key(client_id, *g);
}

  char* 
cpp_server_process_query(void* pir, char* q, uint64_t len_total_bytes, uint64_t num_logical_entries, uint64_t* rlen_total_bytes, uint64_t* rnum_logical_entries, int client_id)
{
  string str(q);
  pirQuery query = deserialize_ciphertexts(num_logical_entries, str, len_total_bytes/num_logical_entries);

  pirReply reply = ((PIRServer*) pir)->generate_reply(query, client_id);

  string s = serialize_ciphertexts(reply);

  *rlen_total_bytes = s.length();
  *rnum_logical_entries = reply.size();

  char *outptr, *result; 
  result = (char*)calloc(*rlen_total_bytes, sizeof(char));
  memcpy(result, s.c_str(), s.length());
  return result;
}


  void 
cpp_server_free(void *pir)
{
  delete (PIRServer*) pir;
}
