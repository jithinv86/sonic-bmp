#include "BMPTlv.h"
#include "BGPOpenValidation.h"

#ifdef _WIN32
typedef unsigned char u_char;
#endif

#include "bgp_common.h"

#include <array>
#include <cstdlib>
#include <cstdint>
#include <vector>

#define CHECK(condition) do { if (!(condition)) std::abort(); } while (false)

namespace {

void testCursorEndAndTruncatedHeader() {
    bmp::TlvView tlv = {};
    bmp::TlvCursor empty(nullptr, 0);
    CHECK(empty.next(tlv) == bmp::TlvReadResult::END);

    const unsigned char short_header[] = {0x00, 0x01, 0x00};
    for (size_t length = 1; length <= sizeof(short_header); ++length) {
        bmp::TlvCursor cursor(short_header, length);
        CHECK(cursor.next(tlv) == bmp::TlvReadResult::TRUNCATED_HEADER);
        CHECK(cursor.remaining() == length);
    }
}

void testCursorRejectsTruncatedValue() {
    const unsigned char data[] = {
        0x00, 0x02, 0x00, 0x03,
        'a', 'b'
    };
    bmp::TlvView tlv = {};
    bmp::TlvCursor cursor(data, sizeof(data));

    CHECK(cursor.next(tlv) == bmp::TlvReadResult::TRUNCATED_VALUE);
    CHECK(cursor.remaining() == sizeof(data));
}

void testCursorHandlesEmptyAndMultipleTlvs() {
    const unsigned char data[] = {
        0x00, 0x03, 0x00, 0x00,
        0x12, 0x34, 0x00, 0x03, 'x', 'y', 'z'
    };
    bmp::TlvView tlv = {};
    bmp::TlvCursor cursor(data, sizeof(data));

    CHECK(cursor.next(tlv) == bmp::TlvReadResult::OK);
    CHECK(tlv.type == 3);
    CHECK(tlv.length == 0);
    CHECK(tlv.value == data + 4);
    CHECK(cursor.remaining() == 7);

    CHECK(cursor.next(tlv) == bmp::TlvReadResult::OK);
    CHECK(tlv.type == 0x1234);
    CHECK(tlv.length == 3);
    CHECK(tlv.value[0] == 'x');
    CHECK(tlv.value[1] == 'y');
    CHECK(tlv.value[2] == 'z');
    CHECK(cursor.remaining() == 0);
    CHECK(cursor.next(tlv) == bmp::TlvReadResult::END);
}

void testStringCopyBoundaries() {
    struct GuardedBuffer {
        uint8_t before;
        char data[5];
        uint8_t after;
    };

    const unsigned char value[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    GuardedBuffer buffer = {0xA5, {}, 0x5A};

    CHECK(bmp::copyString(buffer.data, sizeof(buffer.data), value, 0) == 0);
    CHECK(buffer.data[0] == '\0');

    CHECK(bmp::copyString(buffer.data, sizeof(buffer.data), value, 4) == 4);
    CHECK(buffer.data[0] == 'a');
    CHECK(buffer.data[3] == 'd');
    CHECK(buffer.data[4] == '\0');

    CHECK(bmp::copyString(buffer.data, sizeof(buffer.data), value, 5) == 4);
    CHECK(buffer.data[4] == '\0');

    CHECK(bmp::copyString(buffer.data, sizeof(buffer.data), value, 6) == 4);
    CHECK(buffer.before == 0xA5);
    CHECK(buffer.after == 0x5A);
}

void testLargeStringCopyBoundaries() {
    std::vector<unsigned char> value(4097, 'q');
    std::array<unsigned char, 4098> guarded = {};
    guarded.front() = 0xA5;
    guarded.back() = 0x5A;

    char *destination = reinterpret_cast<char *>(guarded.data() + 1);
    for (size_t length : {size_t(4095), size_t(4096), size_t(4097)}) {
        guarded.front() = 0xA5;
        guarded.back() = 0x5A;
        CHECK(bmp::copyString(destination, 4096, value.data(), length) == 4095);
        CHECK(destination[4094] == 'q');
        CHECK(destination[4095] == '\0');
        CHECK(guarded.front() == 0xA5);
        CHECK(guarded.back() == 0x5A);
    }
}

void testLongTlvAdvancesByEncodedLength() {
    const size_t value_length = 4097;
    std::vector<unsigned char> data(4 + value_length + 5, 'q');
    data[0] = 0x00;
    data[1] = 0x00;
    data[2] = 0x10;
    data[3] = 0x01;

    size_t next = 4 + value_length;
    data[next] = 0x00;
    data[next + 1] = 0x02;
    data[next + 2] = 0x00;
    data[next + 3] = 0x01;
    data[next + 4] = 'z';

    bmp::TlvView tlv = {};
    bmp::TlvCursor cursor(data.data(), data.size());

    CHECK(cursor.next(tlv) == bmp::TlvReadResult::OK);
    CHECK(tlv.type == 0);
    CHECK(tlv.length == value_length);
    CHECK(cursor.remaining() == 5);

    CHECK(cursor.next(tlv) == bmp::TlvReadResult::OK);
    CHECK(tlv.type == 2);
    CHECK(tlv.length == 1);
    CHECK(tlv.value[0] == 'z');
    CHECK(cursor.remaining() == 0);
}

void testEmbeddedNullIsCopiedAsData() {
    const unsigned char value[] = {'a', '\0', 'b'};
    char destination[5] = {};

    CHECK(bmp::copyString(destination, sizeof(destination), value, sizeof(value)) == 3);
    CHECK(destination[0] == 'a');
    CHECK(destination[1] == '\0');
    CHECK(destination[2] == 'b');
    CHECK(destination[3] == '\0');
}

void testBgpMessageLengthValidation() {
    std::array<unsigned char, BGP_OPEN_MSG_MIN_LEN> data = {};
    data[16] = 0x00;
    data[17] = BGP_OPEN_MSG_MIN_LEN;
    data[18] = 0x01;

    uint16_t message_length = 0;
    CHECK(bgp::validateMessageLength(data.data(), data.size(), BGP_OPEN_MSG_MIN_LEN,
                                     message_length));
    CHECK(message_length == BGP_OPEN_MSG_MIN_LEN);

    data[17] = BGP_MSG_HDR_LEN - 1;
    CHECK(!bgp::validateMessageLength(data.data(), data.size(), BGP_MSG_HDR_LEN,
                                      message_length));

    data[17] = BGP_OPEN_MSG_MIN_LEN + 1;
    CHECK(!bgp::validateMessageLength(data.data(), data.size(), BGP_MSG_HDR_LEN,
                                      message_length));

    CHECK(!bgp::validateMessageLength(data.data(), BGP_MSG_HDR_LEN - 1,
                                      BGP_MSG_HDR_LEN, message_length));
}

void testBgpOpenPayloadValidation() {
    const unsigned char empty_parameters[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 0
    };
    CHECK(bgp::validateOpenPayload(empty_parameters, sizeof(empty_parameters)));

    const unsigned char valid_parameters[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 8,
        2, 6, 2, 0, 65, 2, 0, 1
    };
    CHECK(bgp::validateOpenPayload(valid_parameters, sizeof(valid_parameters)));

    std::vector<unsigned char> malformed(valid_parameters,
                                          valid_parameters + sizeof(valid_parameters));
    malformed[9] = 7;
    CHECK(!bgp::validateOpenPayload(malformed.data(), malformed.size()));

    malformed.assign(valid_parameters, valid_parameters + sizeof(valid_parameters));
    malformed[11] = 7;
    CHECK(!bgp::validateOpenPayload(malformed.data(), malformed.size()));

    malformed.assign(valid_parameters, valid_parameters + sizeof(valid_parameters));
    malformed[13] = 5;
    CHECK(!bgp::validateOpenPayload(malformed.data(), malformed.size()));

    const unsigned char truncated_parameter_header[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 1, 2
    };
    CHECK(!bgp::validateOpenPayload(truncated_parameter_header,
                                    sizeof(truncated_parameter_header)));

    const unsigned char invalid_add_path[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 7,
        2, 5, 69, 3, 0, 1, 1
    };
    CHECK(!bgp::validateOpenPayload(invalid_add_path, sizeof(invalid_add_path)));

    const unsigned char invalid_multiprotocol[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 7,
        2, 5, 1, 3, 0, 1, 1
    };
    CHECK(!bgp::validateOpenPayload(invalid_multiprotocol,
                                    sizeof(invalid_multiprotocol)));
}

} // namespace

int main() {
    testCursorEndAndTruncatedHeader();
    testCursorRejectsTruncatedValue();
    testCursorHandlesEmptyAndMultipleTlvs();
    testStringCopyBoundaries();
    testLargeStringCopyBoundaries();
    testLongTlvAdvancesByEncodedLength();
    testEmbeddedNullIsCopiedAsData();
    testBgpMessageLengthValidation();
    testBgpOpenPayloadValidation();
    return 0;
}
