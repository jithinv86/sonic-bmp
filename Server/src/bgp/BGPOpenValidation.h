#ifndef BGP_OPEN_VALIDATION_H_
#define BGP_OPEN_VALIDATION_H_

#include <cstddef>
#include <cstdint>

namespace bgp {

inline bool validateOpenParameters(const unsigned char *data, size_t size) {
    const uint8_t capability_parameter_type = 2;
    const uint8_t multiprotocol_capability = 1;
    const uint8_t add_path_capability = 69;
    size_t offset = 0;

    while (offset < size) {
        if (size - offset < 2) {
            return false;
        }

        const uint8_t type = data[offset];
        const size_t parameter_length = data[offset + 1];
        offset += 2;
        if (parameter_length > size - offset) {
            return false;
        }

        if (type == capability_parameter_type) {
            size_t capability_offset = 0;
            while (capability_offset < parameter_length) {
                if (parameter_length - capability_offset < 2) {
                    return false;
                }

                const uint8_t code = data[offset + capability_offset];
                const size_t capability_length = data[offset + capability_offset + 1];
                capability_offset += 2;
                if (capability_length > parameter_length - capability_offset) {
                    return false;
                }
                if (code == multiprotocol_capability && capability_length != 4) {
                    return false;
                }
                if (code == add_path_capability && capability_length % 4 != 0) {
                    return false;
                }
                capability_offset += capability_length;
            }
        }

        offset += parameter_length;
    }

    return true;
}

inline bool validateOpenPayload(const unsigned char *data, size_t size) {
    const size_t open_header_length = 10;
    if (data == nullptr || size < open_header_length) {
        return false;
    }

    const size_t parameter_length = data[open_header_length - 1];
    return parameter_length == size - open_header_length &&
           validateOpenParameters(data + open_header_length, parameter_length);
}

} // namespace bgp

#endif
