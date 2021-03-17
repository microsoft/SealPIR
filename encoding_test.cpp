#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>

using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {
    uint64_t number_of_items = 1 << 12;
    uint64_t size_per_item = 288; // in bytes
    uint32_t N = 4096;

    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 20; 
    uint32_t d = 1;

    EncryptionParameters params(scheme_type::bfv);
    PirParams pir_params;

    // Generates all parameters
    cout << "Main: Generating all parameters" << endl;
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    logt = floor(log2(params.plain_modulus().value()));

    cout << "Main: Initializing the database (this may take some time) ..." << endl;

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

    shared_ptr<SEALContext> context = make_shared<SEALContext>(params, true);
    unique_ptr<KeyGenerator> keygen = make_unique<KeyGenerator>(*context);
    
    PublicKey public_key;
    keygen->create_public_key(public_key);
    
    unique_ptr<Encryptor> encryptor = make_unique<Encryptor>(*context, public_key);

    SecretKey secret_key = keygen->secret_key();
    unique_ptr<Decryptor> decryptor = make_unique<Decryptor>(*context, secret_key);

    unique_ptr<Evaluator> evaluator = make_unique<Evaluator>(*context);


    uint64_t ele_per_ptxt = elements_per_ptxt(logt, N, size_per_item);
    uint64_t bytes_per_ptxt = ele_per_ptxt * size_per_item;

    uint64_t db_size = number_of_items * size_per_item;

    uint64_t coeff_per_ptxt = ele_per_ptxt * coefficients_per_element(logt, size_per_item);
    assert(coeff_per_ptxt <= N);


    vector<uint64_t> coefficients = bytes_to_coeffs(logt, db.get(), size_per_item);
    uint64_t used = coefficients.size();

    assert(used <= coeff_per_ptxt);

    // Pad the rest with 1s
    for (uint64_t j = 0; j < (N - used); j++) {
        coefficients.push_back(1);
    }

    Plaintext plain;
    vector_to_plaintext(coefficients, plain);

    //cout << "Plaintext: " << plain.to_string() << endl;

    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, plain, elems.data(), (N * logt) / 8);

    bool failed = false;
    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[i] != db_copy.get()[i]) {
            cout << "Main: elems " << (int)elems[i] << ", db "
                 << (int) db_copy.get()[i] << endl;
            cout << "Main: PIR result wrong at " << i <<  endl;
            failed = true;
        }
    }
    if(failed){
        return -1;
    }
    else{
        cout << "succeeded" << endl;
    }

}