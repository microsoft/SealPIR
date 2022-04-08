#include "pir_server.hpp"
#include "pir_client.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

PIRServer::PIRServer(const EncryptionParameters &enc_params,
                     const PirParams &pir_params)
    : enc_params_(enc_params), pir_params_(pir_params),
      is_db_preprocessed_(false) {
  context_ = make_shared<SEALContext>(enc_params, true);
  evaluator_ = make_unique<Evaluator>(*context_);
  encoder_ = make_unique<BatchEncoder>(*context_);
}

void PIRServer::preprocess_database() {
  if (!is_db_preprocessed_) {

    for (uint32_t i = 0; i < db_->size(); i++) {
      evaluator_->transform_to_ntt_inplace(db_->operator[](i),
                                           context_->first_parms_id());
    }

    is_db_preprocessed_ = true;
  }
}

// Server takes over ownership of db and will free it when it exits
void PIRServer::set_database(unique_ptr<vector<Plaintext>> &&db) {
  if (!db) {
    throw invalid_argument("db cannot be null");
  }

  db_ = move(db);
  is_db_preprocessed_ = false;
}

void PIRServer::set_database(const std::unique_ptr<const uint8_t[]> &bytes,
                             uint64_t ele_num, uint64_t ele_size) {

  uint32_t logt = floor(log2(enc_params_.plain_modulus().value()));
  uint32_t N = enc_params_.poly_modulus_degree();

  // number of FV plaintexts needed to represent all elements
  uint64_t num_of_plaintexts = pir_params_.num_of_plaintexts;

  // number of FV plaintexts needed to create the d-dimensional matrix
  uint64_t prod = 1;
  for (uint32_t i = 0; i < pir_params_.nvec.size(); i++) {
    prod *= pir_params_.nvec[i];
  }
  uint64_t matrix_plaintexts = prod;

  assert(num_of_plaintexts <= matrix_plaintexts);

  auto result = make_unique<vector<Plaintext>>();
  result->reserve(matrix_plaintexts);

  uint64_t ele_per_ptxt = pir_params_.elements_per_plaintext;
  uint64_t bytes_per_ptxt = ele_per_ptxt * ele_size;

  uint64_t db_size = ele_num * ele_size;

  uint64_t coeff_per_ptxt =
      ele_per_ptxt * coefficients_per_element(logt, ele_size);
  assert(coeff_per_ptxt <= N);

  cout << "Elements per plaintext: " << ele_per_ptxt << endl;
  cout << "Coeff per ptxt: " << coeff_per_ptxt << endl;
  cout << "Bytes per plaintext: " << bytes_per_ptxt << endl;

  uint32_t offset = 0;

  for (uint64_t i = 0; i < num_of_plaintexts; i++) {

    uint64_t process_bytes = 0;

    if (db_size <= offset) {
      break;
    } else if (db_size < offset + bytes_per_ptxt) {
      process_bytes = db_size - offset;
    } else {
      process_bytes = bytes_per_ptxt;
    }
    assert(process_bytes % ele_size == 0);
    uint64_t ele_in_chunk = process_bytes / ele_size;

    // Get the coefficients of the elements that will be packed in plaintext i
    vector<uint64_t> coefficients(coeff_per_ptxt);
    for (uint64_t ele = 0; ele < ele_in_chunk; ele++) {
      vector<uint64_t> element_coeffs = bytes_to_coeffs(
          logt, bytes.get() + offset + (ele_size * ele), ele_size);
      std::copy(element_coeffs.begin(), element_coeffs.end(),
                coefficients.begin() +
                    (coefficients_per_element(logt, ele_size) * ele));
    }

    offset += process_bytes;

    uint64_t used = coefficients.size();

    assert(used <= coeff_per_ptxt);

    // Pad the rest with 1s
    for (uint64_t j = 0; j < (pir_params_.slot_count - used); j++) {
      coefficients.push_back(1);
    }

    Plaintext plain;
    encoder_->encode(coefficients, plain);
    // cout << i << "-th encoded plaintext = " << plain.to_string() << endl;
    result->push_back(move(plain));
  }

  // Add padding to make database a matrix
  uint64_t current_plaintexts = result->size();
  assert(current_plaintexts <= num_of_plaintexts);

#ifdef DEBUG
  cout << "adding: " << matrix_plaintexts - current_plaintexts
       << " FV plaintexts of padding (equivalent to: "
       << (matrix_plaintexts - current_plaintexts) *
              elements_per_ptxt(logtp, N, ele_size)
       << " elements)" << endl;
#endif

  vector<uint64_t> padding(N, 1);

  for (uint64_t i = 0; i < (matrix_plaintexts - current_plaintexts); i++) {
    Plaintext plain;
    vector_to_plaintext(padding, plain);
    result->push_back(plain);
  }

  set_database(move(result));
}

void PIRServer::set_galois_key(uint32_t client_id, seal::GaloisKeys galkey) {
  galoisKeys_[client_id] = galkey;
}

PirQuery PIRServer::deserialize_query(stringstream &stream) {
  PirQuery q;

  for (uint32_t i = 0; i < pir_params_.d; i++) {
    // number of ciphertexts needed to encode the index for dimension i
    // keeping into account that each ciphertext can encode up to
    // poly_modulus_degree indexes In most cases this is usually 1.
    uint32_t ctx_per_dimension =
        ceil((pir_params_.nvec[i] + 0.0) / enc_params_.poly_modulus_degree());

    vector<Ciphertext> cs;
    for (uint32_t j = 0; j < ctx_per_dimension; j++) {
      Ciphertext c;
      c.load(*context_, stream);
      cs.push_back(c);
    }

    q.push_back(cs);
  }

  return q;
}

int PIRServer::serialize_reply(PirReply &reply, stringstream &stream) {
  int output_size = 0;
  for (int i = 0; i < reply.size(); i++) {
    evaluator_->mod_switch_to_inplace(reply[i], context_->last_parms_id());
    output_size += reply[i].save(stream);
  }
  return output_size;
}

PirReply PIRServer::generate_reply(PirQuery &query, uint32_t client_id) {

  vector<uint64_t> nvec = pir_params_.nvec;
  uint64_t product = 1;

  for (uint32_t i = 0; i < nvec.size(); i++) {
    product *= nvec[i];
  }

  auto coeff_count = enc_params_.poly_modulus_degree();

  vector<Plaintext> *cur = db_.get();
  vector<Plaintext> intermediate_plain; // decompose....

  auto pool = MemoryManager::GetPool();

  int N = enc_params_.poly_modulus_degree();

  int logt = floor(log2(enc_params_.plain_modulus().value()));

  for (uint32_t i = 0; i < nvec.size(); i++) {
    cout << "Server: " << i + 1 << "-th recursion level started " << endl;

    vector<Ciphertext> expanded_query;

    uint64_t n_i = nvec[i];
    cout << "Server: n_i = " << n_i << endl;
    cout << "Server: expanding " << query[i].size() << " query ctxts" << endl;
    for (uint32_t j = 0; j < query[i].size(); j++) {
      uint64_t total = N;
      if (j == query[i].size() - 1) {
        total = n_i % N;
      }
      cout << "-- expanding one query ctxt into " << total << " ctxts " << endl;
      vector<Ciphertext> expanded_query_part =
          expand_query(query[i][j], total, client_id);
      expanded_query.insert(
          expanded_query.end(),
          std::make_move_iterator(expanded_query_part.begin()),
          std::make_move_iterator(expanded_query_part.end()));
      expanded_query_part.clear();
    }
    cout << "Server: expansion done " << endl;
    if (expanded_query.size() != n_i) {
      cout << " size mismatch!!! " << expanded_query.size() << ", " << n_i
           << endl;
    }

    // Transform expanded query to NTT, and ...
    for (uint32_t jj = 0; jj < expanded_query.size(); jj++) {
      evaluator_->transform_to_ntt_inplace(expanded_query[jj]);
    }

    // Transform plaintext to NTT. If database is pre-processed, can skip
    if ((!is_db_preprocessed_) || i > 0) {
      for (uint32_t jj = 0; jj < cur->size(); jj++) {
        evaluator_->transform_to_ntt_inplace((*cur)[jj],
                                             context_->first_parms_id());
      }
    }

    for (uint64_t k = 0; k < product; k++) {
      if ((*cur)[k].is_zero()) {
        cout << k + 1 << "/ " << product << "-th ptxt = 0 " << endl;
      }
    }

    product /= n_i;

    vector<Ciphertext> intermediateCtxts(product);
    Ciphertext temp;

    for (uint64_t k = 0; k < product; k++) {

      evaluator_->multiply_plain(expanded_query[0], (*cur)[k],
                                 intermediateCtxts[k]);

      for (uint64_t j = 1; j < n_i; j++) {
        evaluator_->multiply_plain(expanded_query[j], (*cur)[k + j * product],
                                   temp);
        evaluator_->add_inplace(intermediateCtxts[k],
                                temp); // Adds to first component.
      }
    }

    for (uint32_t jj = 0; jj < intermediateCtxts.size(); jj++) {
      evaluator_->transform_from_ntt_inplace(intermediateCtxts[jj]);
      // print intermediate ctxts?
      // cout << "const term of ctxt " << jj << " = " <<
      // intermediateCtxts[jj][0] << endl;
    }

    if (i == nvec.size() - 1) {
      return intermediateCtxts;
    } else {
      intermediate_plain.clear();
      intermediate_plain.reserve(pir_params_.expansion_ratio * product);
      cur = &intermediate_plain;

      for (uint64_t rr = 0; rr < product; rr++) {
        EncryptionParameters parms;
        if (pir_params_.enable_mswitching) {
          evaluator_->mod_switch_to_inplace(intermediateCtxts[rr],
                                            context_->last_parms_id());
          parms = context_->last_context_data()->parms();
        } else {
          parms = context_->first_context_data()->parms();
        }

        vector<Plaintext> plains =
            decompose_to_plaintexts(parms, intermediateCtxts[rr]);

        for (uint32_t jj = 0; jj < plains.size(); jj++) {
          intermediate_plain.emplace_back(plains[jj]);
        }
      }
      product = intermediate_plain.size(); // multiply by expansion rate.
    }
    cout << "Server: " << i + 1 << "-th recursion level finished " << endl;
    cout << endl;
  }
  cout << "reply generated!  " << endl;
  // This should never get here
  assert(0);
  vector<Ciphertext> fail(1);
  return fail;
}

inline vector<Ciphertext> PIRServer::expand_query(const Ciphertext &encrypted,
                                                  uint32_t m,
                                                  uint32_t client_id) {

  GaloisKeys &galkey = galoisKeys_[client_id];

  // Assume that m is a power of 2. If not, round it to the next power of 2.
  uint32_t logm = ceil(log2(m));
  Plaintext two("2");

  vector<int> galois_elts;
  auto n = enc_params_.poly_modulus_degree();
  if (logm > ceil(log2(n))) {
    throw logic_error("m > n is not allowed.");
  }
  for (int i = 0; i < ceil(log2(n)); i++) {
    galois_elts.push_back((n + exponentiate_uint(2, i)) /
                          exponentiate_uint(2, i));
  }

  vector<Ciphertext> temp;
  temp.push_back(encrypted);
  Ciphertext tempctxt;
  Ciphertext tempctxt_rotated;
  Ciphertext tempctxt_shifted;
  Ciphertext tempctxt_rotatedshifted;

  for (uint32_t i = 0; i < logm - 1; i++) {
    vector<Ciphertext> newtemp(temp.size() << 1);
    // temp[a] = (j0 = a (mod 2**i) ? ) : Enc(x^{j0 - a}) else Enc(0).  With
    // some scaling....
    int index_raw = (n << 1) - (1 << i);
    int index = (index_raw * galois_elts[i]) % (n << 1);

    for (uint32_t a = 0; a < temp.size(); a++) {

      evaluator_->apply_galois(temp[a], galois_elts[i], galkey,
                               tempctxt_rotated);

      // cout << "rotate " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_rotated) << ", ";

      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);

      // cout << "mul by x^pow: " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_shifted) << ", ";

      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);

      // cout << "mul by x^pow: " <<
      // client.decryptor_->invariant_noise_budget(tempctxt_rotatedshifted) <<
      // ", ";

      // Enc(2^i x^j) if j = 0 (mod 2**i).
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                      newtemp[a + temp.size()]);
    }
    temp = newtemp;
    /*
    cout << "end: ";
    for (int h = 0; h < temp.size();h++){
        cout << client.decryptor_->invariant_noise_budget(temp[h]) << ", ";
    }
    cout << endl;
    */
  }
  // Last step of the loop
  vector<Ciphertext> newtemp(temp.size() << 1);
  int index_raw = (n << 1) - (1 << (logm - 1));
  int index = (index_raw * galois_elts[logm - 1]) % (n << 1);
  for (uint32_t a = 0; a < temp.size(); a++) {
    if (a >= (m - (1 << (logm - 1)))) { // corner case.
      evaluator_->multiply_plain(temp[a], two,
                                 newtemp[a]); // plain multiplication by 2.
      // cout << client.decryptor_->invariant_noise_budget(newtemp[a]) << ", ";
    } else {
      evaluator_->apply_galois(temp[a], galois_elts[logm - 1], galkey,
                               tempctxt_rotated);
      evaluator_->add(temp[a], tempctxt_rotated, newtemp[a]);
      multiply_power_of_X(temp[a], tempctxt_shifted, index_raw);
      multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index);
      evaluator_->add(tempctxt_shifted, tempctxt_rotatedshifted,
                      newtemp[a + temp.size()]);
    }
  }

  vector<Ciphertext>::const_iterator first = newtemp.begin();
  vector<Ciphertext>::const_iterator last = newtemp.begin() + m;
  vector<Ciphertext> newVec(first, last);

  return newVec;
}

inline void PIRServer::multiply_power_of_X(const Ciphertext &encrypted,
                                           Ciphertext &destination,
                                           uint32_t index) {

  auto coeff_mod_count = enc_params_.coeff_modulus().size() - 1;
  auto coeff_count = enc_params_.poly_modulus_degree();
  auto encrypted_count = encrypted.size();

  // cout << "coeff mod count for power of X = " << coeff_mod_count << endl;
  // cout << "coeff count for power of X = " << coeff_count << endl;

  // First copy over.
  destination = encrypted;

  // Prepare for destination
  // Multiply X^index for each ciphertext polynomial
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                     coeff_count, index,
                                     enc_params_.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}

void PIRServer::simple_set(uint64_t index, Plaintext pt) {
  if (is_db_preprocessed_) {
    evaluator_->transform_to_ntt_inplace(pt, context_->first_parms_id());
  }
  db_->operator[](index) = pt;
}

Ciphertext PIRServer::simple_query(uint64_t index) {
  // There is no transform_from_ntt that takes a plaintext
  Ciphertext ct;
  Plaintext pt = db_->operator[](index);
  evaluator_->multiply_plain(one_, pt, ct);
  evaluator_->transform_from_ntt_inplace(ct);
  return ct;
}

void PIRServer::set_one_ct(Ciphertext one) {
  one_ = one;
  evaluator_->transform_to_ntt_inplace(one_);
}
