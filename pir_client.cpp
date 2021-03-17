#include "pir_client.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

PIRClient::PIRClient(const EncryptionParameters &params,
                     const PirParams &pir_parms) :
    params_(params){

    newcontext_ = make_shared<SEALContext>(params, true);

    pir_params_ = pir_parms;

    keygen_ = make_unique<KeyGenerator>(*newcontext_);
    
    PublicKey public_key;
    keygen_->create_public_key(public_key);
    encryptor_ = make_unique<Encryptor>(*newcontext_, public_key);

    SecretKey secret_key = keygen_->secret_key();
    decryptor_ = make_unique<Decryptor>(*newcontext_, secret_key);

    evaluator_ = make_unique<Evaluator>(*newcontext_);
}


PirQuery PIRClient::generate_query(uint64_t desiredIndex) {

    indices_ = compute_indices(desiredIndex, pir_params_.nvec);

    vector<vector<Ciphertext> > result(pir_params_.d);
    int N = params_.poly_modulus_degree(); 

    Plaintext pt(params_.poly_modulus_degree());
    for (uint32_t i = 0; i < indices_.size(); i++) {
        uint32_t num_ptxts = ceil( (pir_params_.nvec[i] + 0.0) / N);
        // initialize result. 
        cout << "Client: index " << i + 1  <<  "/ " <<  indices_.size() << " = " << indices_[i] << endl; 
        cout << "Client: number of ctxts needed for query = " << num_ptxts << endl;
        
        for (uint32_t j =0; j < num_ptxts; j++){
            pt.set_zero();
            if (indices_[i] > N*(j+1) || indices_[i] < N*j){
#ifdef DEBUG
                cout << "Client: coming here: so just encrypt zero." << endl; 
#endif 
                // just encrypt zero
            } else{
#ifdef DEBUG
                cout << "Client: encrypting a real thing " << endl; 
#endif 
                uint64_t real_index = indices_[i] - N*j; 
                uint64_t n_i = pir_params_.nvec[i];
                uint64_t total = N; 
                if (j == num_ptxts - 1){
                    total = n_i % N; 
                }
                uint64_t log_total = ceil(log2(total));

                cout << "Client: Inverting " << pow(2, log_total) << endl;
                pt[real_index] = InvertMod(pow(2, log_total), params_.plain_modulus());
            }
            Ciphertext dest;
            encryptor_->encrypt(pt, dest);
            result[i].push_back(dest);
        }   
    }

    return result;
}

uint64_t PIRClient::get_fv_index(uint64_t element_idx, uint64_t ele_size) {
    auto N = params_.poly_modulus_degree();
    auto logt = floor(log2(params_.plain_modulus().value()));

    auto ele_per_ptxt = elements_per_ptxt(logt, N, ele_size);
    return static_cast<uint64_t>(element_idx / ele_per_ptxt);
}

uint64_t PIRClient::get_fv_offset(uint64_t element_idx, uint64_t ele_size) {
    uint32_t N = params_.poly_modulus_degree();
    uint32_t logt = floor(log2(params_.plain_modulus().value()));

    uint64_t ele_per_ptxt = elements_per_ptxt(logt, N, ele_size);
    return element_idx % ele_per_ptxt;
}

Plaintext PIRClient::decode_reply(PirReply reply) {
    uint32_t exp_ratio = pir_params_.expansion_ratio;
    uint32_t recursion_level = pir_params_.d;

    vector<Ciphertext> temp = reply;

    uint64_t t = params_.plain_modulus().value();

    for (uint32_t i = 0; i < recursion_level; i++) {
        cout << "Client: " << i + 1 << "/ " << recursion_level << "-th decryption layer started." << endl; 
        vector<Ciphertext> newtemp;
        vector<Plaintext> tempplain;

        for (uint32_t j = 0; j < temp.size(); j++) {
            Plaintext ptxt;
            decryptor_->decrypt(temp[j], ptxt);
#ifdef DEBUG
            cout << "Client: reply noise budget = " << decryptor_->invariant_noise_budget(temp[j]) << endl; 
#endif
            
            //cout << "decoded (and scaled) plaintext = " << ptxt.to_string() << endl;
            tempplain.push_back(ptxt);

#ifdef DEBUG
            cout << "recursion level : " << i << " noise budget :  ";
            cout << decryptor_->invariant_noise_budget(temp[j]) << endl;
#endif

            if ((j + 1) % exp_ratio == 0 && j > 0) {
                // Combine into one ciphertext.
                Ciphertext combined = compose_to_ciphertext(tempplain);
                newtemp.push_back(combined);
                tempplain.clear();
                // cout << "Client: const term of ciphertext = " << combined[0] << endl; 
            }
        }
        cout << "Client: done." << endl; 
        cout << endl; 
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
    vector<uint32_t> galois_elts;
    int N = params_.poly_modulus_degree();
    int logN = get_power_of_two(N);

    //cout << "printing galois elements...";
    for (int i = 0; i < logN; i++) {
        galois_elts.push_back((N + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
//#ifdef DEBUG
        // cout << galois_elts.back() << ", ";
//#endif
    }
    GaloisKeys gal_keys;
    keygen_->create_galois_keys(galois_elts, gal_keys);
    return gal_keys;
}

Ciphertext PIRClient::compose_to_ciphertext(vector<Plaintext> plains) {
    size_t encrypted_count = 2;
    auto coeff_count = params_.poly_modulus_degree();
    auto coeff_mod_count = params_.coeff_modulus().size();
    uint64_t plainMod = params_.plain_modulus().value();
    int logt = floor(log2(plainMod)); 

    Ciphertext result(*newcontext_);
    result.resize(encrypted_count);

    // A triple for loop. Going over polys, moduli, and decomposed index.
    for (int i = 0; i < encrypted_count; i++) {
        uint64_t *encrypted_pointer = result.data(i);

        for (int j = 0; j < coeff_mod_count; j++) {
            // populate one poly at a time.
            // create a polynomial to store the current decomposition value
            // which will be copied into the array to populate it at the current
            // index.
            double logqj = log2(params_.coeff_modulus()[j].value());
            int expansion_ratio = ceil(logqj / logt);
            uint64_t cur = 1;
            // cout << "Client: expansion_ratio = " << expansion_ratio << endl; 

            for (int k = 0; k < expansion_ratio; k++) {
                // Compose here
                const uint64_t *plain_coeff =
                    plains[k + j * (expansion_ratio) + i * (coeff_mod_count * expansion_ratio)]
                        .data();

                for (int m = 0; m < coeff_count; m++) {
                    if (k == 0) {
                        *(encrypted_pointer + m + j * coeff_count) = *(plain_coeff + m) * cur;
                    } else {
                        *(encrypted_pointer + m + j * coeff_count) += *(plain_coeff + m) * cur;
                    }
                }
                // *(encrypted_pointer + coeff_count - 1 + j * coeff_count) = 0;
                cur <<= logt;
            }

            // XXX: Reduction modulo qj. This is needed?
            /*
            for (int m = 0; m < coeff_count; m++) {
                *(encrypted_pointer + m + j * coeff_count) %=
                    params_.coeff_modulus()[j].value();
            }
            */
        }
    }

    return result;
}

Ciphertext PIRClient::get_encrypted_one(){
    Ciphertext one_ct;
    Plaintext one("1");
    encryptor_->encrypt(one, one_ct);
    return one_ct;
}


Plaintext PIRClient::decrypt(seal::Ciphertext ct){
    Plaintext result;
    decryptor_->decrypt(ct, result);
    return result;
}