#include "pir_client.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

PIRClient::PIRClient(const EncryptionParameters &params,
                     const EncryptionParameters &expanded_params, const PirParams &pir_parms) {

    params_ = params;
    SEALContext context(params);

    expanded_params_ = expanded_params;
    SEALContext newcontext(expanded_params);

    pir_params_ = pir_parms;

    keygen_.reset(new KeyGenerator(context));
    encryptor_.reset(new Encryptor(context, keygen_->public_key()));

    SecretKey secret_key = keygen_->secret_key();
    secret_key.mutable_hash_block() = expanded_params.hash_block();

    decryptor_.reset(new Decryptor(newcontext, secret_key));
    evaluator_.reset(new Evaluator(newcontext));
}

void PIRClient::update_parameters(const EncryptionParameters &expanded_params,
                                  const PirParams &pir_params) {

    // The only thing that can change is the plaintext modulus and pir_params
    assert(expanded_params.poly_modulus() == expanded_params_.poly_modulus());
    assert(expanded_params.coeff_modulus() == expanded_params_.coeff_modulus());

    expanded_params_ = expanded_params;
    pir_params_ = pir_params;
    SEALContext newcontext(expanded_params);

    SecretKey secret_key = keygen_->secret_key();
    secret_key.mutable_hash_block() = expanded_params.hash_block();

    decryptor_.reset(new Decryptor(newcontext, secret_key));
    evaluator_.reset(new Evaluator(newcontext));
}

PirQuery PIRClient::generate_query(uint64_t desiredIndex) {

    vector<uint64_t> indices = compute_indices(desiredIndex, pir_params_.nvec);
    vector<Ciphertext> result;

    for (uint32_t i = 0; i < indices.size(); i++) {
        Ciphertext dest;
        encryptor_->encrypt(Plaintext("1x^" + std::to_string(indices[i])), dest);
        dest.mutable_hash_block() = expanded_params_.hash_block();
        result.push_back(dest);
    }

    return result;
}

uint64_t PIRClient::get_fv_index(uint64_t element_idx, uint64_t ele_size) {
    uint32_t N = params_.poly_modulus().coeff_count() - 1;
    uint32_t logtp = ceil(log2(expanded_params_.plain_modulus().value()));

    uint64_t ele_per_ptxt = elements_per_ptxt(logtp, N, ele_size);
    return element_idx / ele_per_ptxt;
}

uint64_t PIRClient::get_fv_offset(uint64_t element_idx, uint64_t ele_size) {
    uint32_t N = params_.poly_modulus().coeff_count() - 1;
    uint32_t logtp = ceil(log2(expanded_params_.plain_modulus().value()));

    uint64_t ele_per_ptxt = elements_per_ptxt(logtp, N, ele_size);
    return element_idx % ele_per_ptxt;
}

Plaintext PIRClient::decode_reply(PirReply reply) {
    uint32_t exp_ratio = pir_params_.expansion_ratio;
    uint32_t recursion_level = pir_params_.d;

    vector<Ciphertext> temp = reply;

    for (uint32_t i = 0; i < recursion_level; i++) {

        vector<Ciphertext> newtemp;
        vector<Plaintext> tempplain;

        for (uint32_t j = 0; j < temp.size(); j++) {
            Plaintext ptxt;
            decryptor_->decrypt(temp[j], ptxt);
            tempplain.push_back(ptxt);

#ifdef DEBUG
            cout << "recursion level : " << i << " noise budget :  ";
            cout << decryptor_->invariant_noise_budget(temp[j]) << endl;
#endif

            if ((j + 1) % exp_ratio == 0 && j > 0) {
                // Combine into one ciphertext.
                Ciphertext combined = compose_to_ciphertext(tempplain);
                newtemp.push_back(combined);
            }
        }

        if (i == recursion_level - 1) {
            assert(temp.size() == 1);
            return tempplain[0];
        } else {
            tempplain.clear();
            temp = newtemp;
        }
    }

    // This should never be called
    assert(0);
    Plaintext fail;
    return fail;
}

GaloisKeys PIRClient::generate_galois_keys() {
    // Generate the Galois keys needed for coeff_select.
    vector<uint64_t> galois_elts;
    int N = params_.poly_modulus().coeff_count() - 1;
    int logN = get_power_of_two(N);

    for (int i = 0; i < logN; i++) {
        galois_elts.push_back((N + exponentiate_uint64(2, i)) / exponentiate_uint64(2, i));
#ifdef DEBUG
        cout << galois_elts.back() << ", ";
#endif
    }

    GaloisKeys galois_keys;
    keygen_->generate_galois_keys(pir_params_.dbc, galois_elts, galois_keys);
    return galois_keys;
}

Ciphertext PIRClient::compose_to_ciphertext(vector<Plaintext> plains) {
    int encrypted_count = 2;
    int coeff_count = expanded_params_.poly_modulus().coeff_count();
    int coeff_mod_count = expanded_params_.coeff_modulus().size();
    uint64_t plainMod = expanded_params_.plain_modulus().value();

    Ciphertext result;
    result.reserve(expanded_params_, encrypted_count);

    // A triple for loop. Going over polys, moduli, and decomposed index.
    for (int i = 0; i < encrypted_count; i++) {
        uint64_t *encrypted_pointer = result.mutable_pointer(i);

        for (int j = 0; j < coeff_mod_count; j++) {
            // populate one poly at a time.
            // create a polynomial to store the current decomposition value
            // which will be copied into the array to populate it at the current
            // index.
            double logqj = log2(expanded_params_.coeff_modulus()[j].value());
            int expansion_ratio = ceil(logqj / log2(plainMod));

            // cout << "expansion ratio = " << expansion_ratio << endl;
            uint64_t cur = 1;

            for (int k = 0; k < expansion_ratio; k++) {

                // Compose here
                const uint64_t *plain_coeff =
                    plains[k + j * (expansion_ratio) + i * (coeff_mod_count * expansion_ratio)]
                        .pointer();

                for (int m = 0; m < coeff_count - 1; m++) {
                    if (k == 0) {
                        *(encrypted_pointer + m + j * coeff_count) = *(plain_coeff + m) * cur;
                    } else {
                        *(encrypted_pointer + m + j * coeff_count) += *(plain_coeff + m) * cur;
                    }
                }

                *(encrypted_pointer + coeff_count - 1 + j * coeff_count) = 0;
                cur *= plainMod;
            }

            // XXX: Reduction modulo qj. This is needed?
            /*
            for (int m = 0; m < coeff_count; m++) {
                *(encrypted_pointer + m + j * coeff_count) %=
                    expanded_params_.coeff_modulus()[j].value();
            }
            */
        }
    }

    result.mutable_hash_block() = expanded_params_.hash_block();
    return result;
}
