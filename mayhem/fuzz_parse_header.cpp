#include <cstdint>

#include "FuzzedDataProvider.h"
#include "npy.hpp"


/**
 * @brief Fuzzing entry point, written to bypass useless ifstream operations.
 * Same logic as the underlying target, main target is the parser anyways
 * @param numpy_contents: Numpy file contents
 */
auto fuzz_me(std::string&& numpy_contents) -> int {
    npy::header_t header = npy::parse_header(numpy_contents);

    // check if the typestring matches the given one
    const npy::dtype_t dtype = npy::dtype_map.at(std::type_index(typeid(double)));

    if (header.dtype.tie() == dtype.tie()) {
        return -1;
    }
    // compute the data size based on the shape
    npy::comp_size(header.shape);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int ret_val = 0;
    std::string numpy_contents = fdp.ConsumeRemainingBytesAsString();

    try {
        ret_val = fuzz_me(std::move(numpy_contents));
    } catch (const std::exception& e) {
        ret_val = -1;
    }



  return ret_val;
}