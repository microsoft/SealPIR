#include "pir.hpp"

using namespace std;
using namespace seal;
using namespace seal::util;

vector<uint64_t> get_dimensions(uint64_t plaintext_num, uint32_t d) {

    assert(d > 0);
    assert(plaintext_num > 0);

    vector<uint64_t> dimensions(d);

    for (uint32_t i = 0; i < d; i++) {
        dimensions[i] = std::max((uint32_t) 2, (uint32_t) floor(pow(plaintext_num, 1.0/d)));
    }

    uint32_t product = 1;
    uint32_t j = 0;

    // if plaintext_num is not a d-power
    if ((double) dimensions[0] != pow(plaintext_num, 1.0 / d)) {
        while  (product < plaintext_num && j < d) {
            product = 1;
            dimensions[j++]++;
            for (uint32_t i = 0; i < d; i++) {
                product *= dimensions[i];
            }
        }
    }

    return dimensions;
}

void gen_params(uint64_t ele_num, uint64_t ele_size, uint32_t N, uint32_t logt,
                uint32_t d, EncryptionParameters &params,
                PirParams &pir_params) {
    
    // Determine the maximum size of each dimension

    // plain modulus = a power of 2 plus 1
    uint64_t plain_mod = (static_cast<uint64_t>(1) << logt) + 1;
    uint64_t plaintext_num = plaintexts_per_db(logt, N, ele_num, ele_size);

#ifdef DEBUG
    cout << "log(plain mod) before expand = " << logt << endl;
    cout << "number of FV plaintexts = " << plaintext_num << endl;
#endif

    vector<SmallModulus> coeff_mod_array;
    uint32_t logq = 0;

    for (uint32_t i = 0; i < 1; i++) {
        coeff_mod_array.emplace_back(SmallModulus());
        coeff_mod_array[i] = DefaultParams::small_mods_60bit(i);
        logq += coeff_mod_array[i].bit_count();
    }

    params.set_poly_modulus_degree(N);
    params.set_coeff_modulus(coeff_mod_array);
    params.set_plain_modulus(plain_mod);

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

void update_params(uint64_t ele_num, uint64_t ele_size, uint32_t d, 
                   const EncryptionParameters &old_params, EncryptionParameters &expanded_params, 
                   PirParams &pir_params) {

    uint32_t logt = ceil(log2(old_params.plain_modulus().value()));
    uint32_t N = old_params.poly_modulus_degree();

    // Determine the maximum size of each dimension
    uint32_t logtp = plainmod_after_expansion(logt, N, d, ele_num, ele_size);

    uint64_t expanded_plain_mod = static_cast<uint64_t>(1) << logtp;
    uint64_t plaintext_num = plaintexts_per_db(logtp, N, ele_num, ele_size);

#ifdef DEBUG
    cout << "log(plain mod) before expand = " << logt << endl;
    cout << "log(plain mod) after expand = " << logtp << endl;
    cout << "number of FV plaintexts = " << plaintext_num << endl;
#endif

    expanded_params.set_poly_modulus_degree(old_params.poly_modulus_degree());
    expanded_params.set_coeff_modulus(old_params.coeff_modulus());
    expanded_params.set_plain_modulus(expanded_plain_mod);

    // Assumes dimension of database is 2
    vector<uint64_t> nvec = get_dimensions(plaintext_num, d);

    uint32_t expansion_ratio = 0;
    for (uint32_t i = 0; i < old_params.coeff_modulus().size(); ++i) {
        double logqi = log2(old_params.coeff_modulus()[i].value());
        expansion_ratio += ceil(logqi / logtp);
    }

    pir_params.d = d;
    pir_params.dbc = 6;
    pir_params.n = plaintext_num;
    pir_params.nvec = nvec;
    pir_params.expansion_ratio = expansion_ratio << 1;
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
    util::set_uint_uint(coeffs.data(), coeff_count, plain.data());
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

inline Ciphertext deserialize_ciphertext(string s) {
    Ciphertext c;
    std::istringstream input(s);
    c.unsafe_load(input);
    return c;
}

vector<Ciphertext> deserialize_ciphertexts(uint32_t count, string s, uint32_t len_ciphertext) {
    vector<Ciphertext> c;
    for (uint32_t i = 0; i < count; i++) {
        c.push_back(deserialize_ciphertext(s.substr(i * len_ciphertext, len_ciphertext)));
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

string serialize_galoiskeys(GaloisKeys g) {
    std::ostringstream output;
    g.save(output);
    return output.str();
}

GaloisKeys *deserialize_galoiskeys(string s) {
    GaloisKeys *g = new GaloisKeys();
    std::istringstream input(s);
    g->unsafe_load(input);
    return g;
}
