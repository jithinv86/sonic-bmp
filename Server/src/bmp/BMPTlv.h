#ifndef BMPTLV_H_
#define BMPTLV_H_

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bmp {

enum class TlvReadResult {
    OK,
    END,
    TRUNCATED_HEADER,
    TRUNCATED_VALUE
};

struct TlvView {
    uint16_t type;
    uint16_t length;
    const unsigned char *value;
};

class TlvCursor {
public:
    TlvCursor(const unsigned char *data, size_t length)
        : cursor(data), remaining_len(length) {
    }

    TlvReadResult next(TlvView &tlv) {
        if (remaining_len == 0)
            return TlvReadResult::END;

        if (remaining_len < 4)
            return TlvReadResult::TRUNCATED_HEADER;

        tlv.type = static_cast<uint16_t>(
            (static_cast<uint16_t>(cursor[0]) << 8) | cursor[1]);
        tlv.length = static_cast<uint16_t>(
            (static_cast<uint16_t>(cursor[2]) << 8) | cursor[3]);

        if (tlv.length > remaining_len - 4)
            return TlvReadResult::TRUNCATED_VALUE;

        tlv.value = cursor + 4;
        cursor += 4 + tlv.length;
        remaining_len -= 4 + tlv.length;
        return TlvReadResult::OK;
    }

    size_t remaining() const {
        return remaining_len;
    }

private:
    const unsigned char *cursor;
    size_t remaining_len;
};

inline size_t copyString(void *destination, size_t capacity,
                         const unsigned char *value, size_t length) {
    if (capacity == 0)
        return 0;

    char *output = static_cast<char *>(destination);
    size_t copy_len = length < capacity - 1 ? length : capacity - 1;

    if (copy_len > 0)
        memcpy(output, value, copy_len);

    output[copy_len] = '\0';
    return copy_len;
}

} // namespace bmp

#endif
