#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <seal/seal.h>
#include <chrono>
#include <memory>
#include <random>
#include <cstdint>
#include <cstddef>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

    //uint64_t number_of_items = 1 << 11;
    //uint64_t number_of_items = 2048;
    uint64_t number_of_items = 1 << 12;

    uint64_t size_per_item = 288; // in bytes
    // uint64_t size_per_item = 1 << 10; // 1 KB.
    // uint64_t size_per_item = 10 << 10; // 10 KB.

    uint32_t N = 2048;
    // Recommended values: (logt, d) = (12, 2) or (8, 1). 
    uint32_t logt = 12; 
    uint32_t d = 5;

    EncryptionParameters params(scheme_type::BFV);
    PirParams pir_params;

    // Generates all parameters
    cout << "Generating all parameters" << endl;
    gen_params(number_of_items, size_per_item, N, logt, d, params, pir_params);

    cout << "Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // For testing purposes only
    auto check_db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    random_device rd;
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
            auto val = rd() % 256;
            db.get()[(i * size_per_item) + j] = val;
            check_db.get()[(i * size_per_item) + j] = val;
        }
    }

    // Initialize PIR Server
    cout << "Initializing server and client" << endl;
    PIRServer server(params, pir_params);

    // Initialize PIR client....
    PIRClient client(params, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    // Set galois key
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);


    // The following can be used to update parameters rather than creating new instances
    // (here it doesn't do anything).
    // cout << "Updating database size to: " << number_of_items << " elements" << endl;
    // update_params(number_of_items, size_per_item, d, params, expanded_params, pir_params);

    cout << "done" << endl;


    // Measure database setup
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    cout << "database pre processed " << endl;
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    // Choose an index of an element in the DB
    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    //uint64_t ele_index = 35; 
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items -1 << "]" << endl;
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item); // offset in FV plaintext
    // Measure query generation
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl; 

    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query(index);
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    // Measure query processing (including expansion)
    auto time_server_s = high_resolution_clock::now();
    //PirQuery query_ser = deserialize_ciphertexts(d, serialize_ciphertexts(query), CIPHER_SIZE);
    PirReply reply = server.generate_reply(query, 0, client);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    // Measure response extraction
    auto time_decode_s = chrono::high_resolution_clock::now();
    Plaintext result = client.decode_reply(reply);
    auto time_decode_e = chrono::high_resolution_clock::now();
    auto time_decode_us = duration_cast<microseconds>(time_decode_e - time_decode_s).count();

    // Convert to elements
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, result, elems.data(), (N * logt) / 8);
    // cout << "printing the bytes...of the supposed item: "; 
    // for (int i = 0; i < size_per_item; i++){
    //     cout << (int) elems[offset*size_per_item + i] << ", "; 
    // }
    // cout << endl; 

    // // cout << "offset = " << offset << endl; 

    // cout << "printing the bytes of real item: "; 
    // for (int i = 0; i < size_per_item; i++){
    //     cout << (int) check_db.get()[ele_index *size_per_item + i] << ", "; 
    // }

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        if (elems[(offset * size_per_item) + i] != check_db.get()[(ele_index * size_per_item) + i]) {
            cout << "elems " << (int)elems[(offset * size_per_item) + i] << ", db "
                 << (int) check_db.get()[(ele_index * size_per_item) + i] << endl;
            cout << "PIR result wrong!" << endl;
            return -1;
        }
    }

    // Output results
    cout << "PIR reseult correct!" << endl;
    cout << "PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    cout << "PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "PIRClient answer decode time: " << time_decode_us / 1000 << " ms" << endl;
    cout << "Reply num ciphertexts: " << reply.size() << endl;

    return 0;
}
