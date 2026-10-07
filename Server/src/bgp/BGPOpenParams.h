#ifndef BGP_OPEN_PARAMS_H_
#define BGP_OPEN_PARAMS_H_

#include <cstddef>
#include <cstdint>

namespace bgp {

/*
 * Bounded readers for BGP OPEN optional parameters and capabilities.
 *
 * Supports both the RFC 4271 encoding (one-octet lengths) and the RFC 9072
 * extended encoding (Optional Parameters Length 255 followed by Non-Ext OP
 * Type 255 and two-octet lengths).  The readers never access bytes beyond
 * the supplied buffer and report truncation instead of rejecting input, so
 * callers can preserve tolerant handling of imperfect router encodings.
 */

const size_t OPEN_FIXED_HDR_LEN = 10;
const uint8_t OPEN_EXTENDED_PARAMS = 255;

struct OpenParamsView {
    const unsigned char *data;
    size_t length;
    bool extended;
    bool truncated;
};

inline bool locateOpenParameters(const unsigned char *payload, size_t size, OpenParamsView &view) {
    view.data = nullptr;
    view.length = 0;
    view.extended = false;
    view.truncated = false;

    if (payload == nullptr || size < OPEN_FIXED_HDR_LEN)
        return false;

    size_t declared = payload[OPEN_FIXED_HDR_LEN - 1];
    size_t offset = OPEN_FIXED_HDR_LEN;

    if (declared == OPEN_EXTENDED_PARAMS && size > OPEN_FIXED_HDR_LEN &&
            payload[OPEN_FIXED_HDR_LEN] == OPEN_EXTENDED_PARAMS) {
        view.extended = true;
        offset = OPEN_FIXED_HDR_LEN + 3;
        if (size < offset) {
            view.truncated = true;
            return true;
        }
        declared = (static_cast<size_t>(payload[OPEN_FIXED_HDR_LEN + 1]) << 8) |
                   payload[OPEN_FIXED_HDR_LEN + 2];
    }

    size_t available = size - offset;
    view.truncated = declared > available;
    view.length = view.truncated ? available : declared;
    view.data = payload + offset;
    return true;
}

enum class OpenReadResult { OK, END, TRUNCATED };

struct OpenElement {
    uint8_t type;
    size_t length;
    const unsigned char *value;
};

/*
 * Iterates optional parameters (when extended_lengths is true, lengths are
 * two octets per RFC 9072) or capabilities (always one-octet lengths).
 */
class OpenElementCursor {
public:
    OpenElementCursor(const unsigned char *data, size_t length, bool extended_lengths)
        : cursor(data), remaining_len(length), header_len(extended_lengths ? 3 : 2) {
    }

    OpenReadResult next(OpenElement &element) {
        if (remaining_len == 0)
            return OpenReadResult::END;
        if (remaining_len < header_len)
            return OpenReadResult::TRUNCATED;

        element.type = cursor[0];
        element.length = header_len == 3
                ? ((static_cast<size_t>(cursor[1]) << 8) | cursor[2])
                : cursor[1];

        if (element.length > remaining_len - header_len)
            return OpenReadResult::TRUNCATED;

        element.value = cursor + header_len;
        cursor += header_len + element.length;
        remaining_len -= header_len + element.length;
        return OpenReadResult::OK;
    }

private:
    const unsigned char *cursor;
    size_t remaining_len;
    size_t header_len;
};

} // namespace bgp

#endif
