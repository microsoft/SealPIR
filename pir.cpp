#include "pir.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

std::vector<std::uint64_t> get_dimensions(std::uint64_t num_of_plaintexts, std::uint32_t d) {

    assert(d > 0);
    assert(num_of_plaintexts > 0);

    std::uint64_t root = max(static_cast<uint32_t>(2),static_cast<uint32_t>(floor(pow(num_of_plaintexts, 1.0/d))));

    std::vector<std::uint64_t> dimensions(d, root);

    for(int i = 0; i < d; i++){
        if(accumulate(dimensions.begin(), dimensions.end(), 1, multiplies<uint64_t>()) > num_of_plaintexts){
            break;
        } 
        dimensions[i] += 1;
    }

    std::uint32_t prod = accumulate(dimensions.begin(), dimensions.end(), 1, multiplies<uint64_t>());
    cout << "Total:" << num_of_plaintexts << endl << "Prod: "
     << prod << endl;
    assert(prod > num_of_plaintexts);
    return dimensions;
}

void gen_encryption_params(std::uint32_t N, std::uint32_t logt,
                           seal::EncryptionParameters &enc_params){
    
    enc_params.set_poly_modulus_degree(N);
    enc_params.set_coeff_modulus(CoeffModulus::BFVDefault(N));
    enc_params.set_plain_modulus(PlainModulus::Batching(N, logt));
}

void verify_encryption_params(const seal::EncryptionParameters &enc_params){
    SEALContext context(enc_params, true);
    if(!context.parameters_set()){
        throw invalid_argument("SEAL parameters not valid.");
    }
    if(!context.using_keyswitching()){
        throw invalid_argument("SEAL parameters do not support key switching.");
    }
    if(!context.first_context_data()->qualifiers().using_batching){
        throw invalid_argument("SEAL parameters do not support batching.");
    }
    return;
}

void gen_pir_params(uint64_t ele_num, uint64_t ele_size, uint32_t d,
                    const EncryptionParameters &enc_params, PirParams &pir_params,
                    bool enable_symmetric, bool enable_batching){
    std::uint32_t N = enc_params.poly_modulus_degree();
    Modulus t = enc_params.plain_modulus();
    std::uint32_t logt = floor(log2(t.value()));

    cout << "logt: " << logt << endl << "N: " << N << endl <<
    "ele_num: " << ele_num << endl << "ele_size: " << ele_size << endl;

    std::uint64_t elements_per_plaintext;
    std::uint64_t num_of_plaintexts;

    if(enable_batching){
        elements_per_plaintext = elements_per_ptxt(logt, N, ele_size);
        num_of_plaintexts = plaintexts_per_db(logt, N, ele_num, ele_size);
    }
    else{
        elements_per_plaintext = 1;
        num_of_plaintexts = ele_num;
    }

    vector<uint64_t> nvec = get_dimensions(num_of_plaintexts, d);

    uint32_t expansion_ratio = 0;
    for (uint32_t i = 0; i < enc_params.coeff_modulus().size(); ++i) {
        double logqi = log2(enc_params.coeff_modulus()[i].value());
        cout << "PIR: logqi = " << logqi << endl;
        expansion_ratio += ceil(logqi / logt);
    }

    if(!enable_symmetric){
        expansion_ratio = expansion_ratio << 1;
    }

    pir_params.enable_symmetric = enable_symmetric;
    pir_params.enable_batching = enable_batching;
    pir_params.ele_num = ele_num;
    pir_params.ele_size = ele_size;
    pir_params.elements_per_plaintext = elements_per_plaintext;
    pir_params.num_of_plaintexts = num_of_plaintexts;
    pir_params.d = d;                 
    pir_params.expansion_ratio = expansion_ratio;           
    pir_params.nvec = nvec;
    pir_params.dbc = 6;
    pir_params.n = num_of_plaintexts;
}


void print_pir_params(const PirParams &pir_params){
    cout << "Pir Params: " << endl;
    cout << "num_of_elements: " << pir_params.ele_num << endl;
    cout << "ele_size: " << pir_params.ele_size << endl;
    cout << "elements_per_plaintext: " << pir_params.elements_per_plaintext << endl;
    cout << "num_of_plaintexts: " << pir_params.num_of_plaintexts << endl;
    cout << "dimension: " << pir_params.d << endl;
    cout << "expansion ratio: " << pir_params.expansion_ratio << endl;
    cout << "dbc: " << pir_params.dbc << endl;
    cout << "n: " << pir_params.n << endl;
}

void gen_params(uint64_t ele_num, uint64_t ele_size, uint32_t N, uint32_t logt,
                uint32_t d, EncryptionParameters &params,
                PirParams &pir_params) {
    

    params.set_poly_modulus_degree(N);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(N));
    params.set_plain_modulus(PlainModulus::Batching(N, logt));

    logt = floor(log2(params.plain_modulus().value()));

    cout << "logt: " << logt << endl << "N: " << N << endl <<
    "ele_num: " << ele_num << endl << "ele_size: " << ele_size << endl;

    uint64_t plaintext_num = plaintexts_per_db(logt, N, ele_num, ele_size);

    vector<uint64_t> nvec = get_dimensions(plaintext_num, d);

    uint32_t expansion_ratio = 0;
    for (uint32_t i = 0; i < params.coeff_modulus().size(); ++i) {
        double logqi = log2(params.coeff_modulus()[i].value());
        cout << "PIR: logqi = " << logqi << endl;
        expansion_ratio += ceil(logqi / logt);
    }

    pir_params.d = d;
    pir_params.dbc = 6;
    pir_params.n = plaintext_num;
    pir_params.nvec = nvec;
    pir_params.expansion_ratio = expansion_ratio << 1; // because one ciphertext = two polys
}


uint32_t plainmod_after_expansion(uint32_t logt, uint32_t N, uint32_t d, 
        uint64_t ele_num, uint64_t ele_size) {

    // Goal: find max logtp such that logtp + ceil(log(ceil(d_root(n)))) <= logt
    // where n = ceil(ele_num / floor(N*logtp / ele_size *8))
    for (uint32_t logtp = logt; logtp >= 2; logtp--) {

        uint64_t n = plaintexts_per_db(logtp, N, ele_num, ele_size);

        if (logtp == logt && n == 1) {
            return logtp - 1;
        }

        if ((double)logtp + ceil(log2(ceil(pow(n, 1.0/(double)d)))) <= logt) {
            return logtp;
        }
    }

    assert(0); // this should never happen
    return logt;
}

// Number of coefficients needed to represent a database element
uint64_t coefficients_per_element(uint32_t logtp, uint64_t ele_size) {
    return ceil(8 * ele_size / (double)logtp);
}

// Number of database elements that can fit in a single FV plaintext
uint64_t elements_per_ptxt(uint32_t logt, uint64_t N, uint64_t ele_size) {
    uint64_t coeff_per_ele = coefficients_per_element(logt, ele_size);
    uint64_t ele_per_ptxt = N / coeff_per_ele;
    assert(ele_per_ptxt > 0);
    return ele_per_ptxt;
}

// Number of FV plaintexts needed to represent the database
uint64_t plaintexts_per_db(uint32_t logtp, uint64_t N, uint64_t ele_num, uint64_t ele_size) {
    uint64_t ele_per_ptxt = elements_per_ptxt(logtp, N, ele_size);
    return ceil((double)ele_num / ele_per_ptxt);
}

vector<uint64_t> bytes_to_coeffs(uint32_t limit, const uint8_t *bytes, uint64_t size) {

    uint64_t size_out = coefficients_per_element(limit, size);
    vector<uint64_t> output(size_out);

    uint32_t room = limit;
    uint64_t *target = &output[0];

    for (uint32_t i = 0; i < size; i++) {
        uint8_t src = bytes[i];
        uint32_t rest = 8;
        while (rest) {
            if (room == 0) {
                target++;
                room = limit;
            }
            uint32_t shift = rest;
            if (room < rest) {
                shift = room;
            }
            *target = *target << shift;
            *target = *target | (src >> (8 - shift));
            src = src << shift;
            room -= shift;
            rest -= shift;
        }
    }

    *target = *target << room;
    return output;
}

void coeffs_to_bytes(uint32_t limit, const Plaintext &coeffs, uint8_t *output, uint32_t size_out) {
    uint32_t room = 8;
    uint32_t j = 0;
    uint8_t *target = output;

    for (uint32_t i = 0; i < coeffs.coeff_count(); i++) {
        uint64_t src = coeffs[i];
        uint32_t rest = limit;
        while (rest && j < size_out) {
            uint32_t shift = rest;
            if (room < rest) {
                shift = room;
            }
            target[j] = target[j] << shift;
            target[j] = target[j] | (src >> (limit - shift));
            src = src << shift;
            room -= shift;
            rest -= shift;
            if (room == 0) {
                j++;
                room = 8;
            }
        }
    }
}

void vector_to_plaintext(const vector<uint64_t> &coeffs, Plaintext &plain) {
    uint32_t coeff_count = coeffs.size();
    plain.resize(coeff_count);
    util::set_uint(coeffs.data(), coeff_count, plain.data());
}

vector<uint64_t> compute_indices(uint64_t desiredIndex, vector<uint64_t> Nvec) {
    uint32_t num = Nvec.size();
    uint64_t product = 1;

    for (uint32_t i = 0; i < num; i++) {
        product *= Nvec[i];
    }

    uint64_t j = desiredIndex;
    vector<uint64_t> result;

    for (uint32_t i = 0; i < num; i++) {

        product /= Nvec[i];
        uint64_t ji = j / product;

        result.push_back(ji);
        j -= ji * product;
    }

    return result;
}

uint64_t invert_mod(uint64_t m, const seal::Modulus& mod) {
  if (mod.uint64_count() > 1) {
    cout << "Mod too big to invert";
  }
  uint64_t inverse = 0;
  if (!seal::util::try_invert_uint_mod(m, mod.value(), inverse)) {
    cout << "Could not invert value";
  }
  return inverse;
}

inline Ciphertext deserialize_ciphertext(string s, shared_ptr<SEALContext> context) {
    Ciphertext c;
    std::istringstream input(s);
    c.unsafe_load(*context, input);
    return c;
}


vector<Ciphertext> deserialize_ciphertexts(uint32_t count, string s, uint32_t len_ciphertext, 
shared_ptr<SEALContext> context) {
    vector<Ciphertext> c;
    for (uint32_t i = 0; i < count; i++) {
        c.push_back(deserialize_ciphertext(s.substr(i * len_ciphertext, len_ciphertext), context));
    }
    return c;
}

PirQuery deserialize_query(uint32_t d, uint32_t count, string s, uint32_t len_ciphertext,
shared_ptr<SEALContext> context) {
    vector<vector<Ciphertext>> c;
    for (uint32_t i = 0; i < d; i++) {
        c.push_back(deserialize_ciphertexts(
              count, 
              s.substr(i * count * len_ciphertext, count * len_ciphertext),
              len_ciphertext, context)
        );
    }
    return c;
}


inline string serialize_ciphertext(Ciphertext c) {
    std::ostringstream output;
    c.save(output);
    return output.str();
}

string serialize_ciphertexts(vector<Ciphertext> c) {
    string s;
    for (uint32_t i = 0; i < c.size(); i++) {
        s.append(serialize_ciphertext(c[i]));
    }
    return s;
}

string serialize_query(vector<vector<Ciphertext>> c) {
    string s;
    for (uint32_t i = 0; i < c.size(); i++) {
      for (uint32_t j = 0; j < c[i].size(); j++) {
        s.append(serialize_ciphertext(c[i][j]));
      }
    }
    return s;
}

string serialize_galoiskeys(GaloisKeys g) {
    std::ostringstream output;
    g.save(output);
    return output.str();
}

GaloisKeys *deserialize_galoiskeys(string s, shared_ptr<SEALContext> context) {
    GaloisKeys *g = new GaloisKeys();
    std::istringstream input(s);
    g->unsafe_load(*context, input);
    return g;
}