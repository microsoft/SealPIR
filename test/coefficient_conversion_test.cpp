#include "pir.hpp"
#include "pir_client.hpp"
#include "pir_server.hpp"
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <seal/seal.h>

using namespace std::chrono;
using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

  const uint32_t logt = 16;
  const uint32_t ele_size = 3;
  const uint32_t num_ele = 3;
  uint8_t bytes[ele_size * num_ele] = {1, 2, 3, 4, 5, 6, 7, 8, 9};

  vector<uint64_t> coeffs;

  cout << "Coeffs: " << endl;
  for (int i = 0; i < num_ele; i++) {
    vector<uint64_t> ele_coeffs =
        bytes_to_coeffs(logt, bytes + (i * ele_size), ele_size);
    for (int j = 0; j < ele_coeffs.size(); j++) {
      cout << ele_coeffs[j] << endl;
      cout << std::bitset<logt>(ele_coeffs[j]) << endl;
      coeffs.push_back(ele_coeffs[j]);
    }
  }

  cout << "Num of Coeffs: " << coeffs.size() << endl;

  uint8_t output[ele_size * num_ele];
  coeffs_to_bytes(logt, coeffs, output, ele_size * num_ele, ele_size);

  cout << "Bytes: " << endl;
  for (int i = 0; i < ele_size * num_ele; i++) {
    cout << (int)output[i] << endl;
  }

  return 0;
}
