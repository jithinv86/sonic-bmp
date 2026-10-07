#include "BMPTlv.h"
#include "BGPOpenParams.h"

#ifdef _WIN32
typedef unsigned char u_char;
#endif

#include "bgp_common.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>

#define CHECK(condition) do { if (!(condition)) { std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); std::abort(); } } while (false)

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

void testBgpMessageFrame() {
    std::array<unsigned char, BGP_OPEN_MSG_MIN_LEN> data = {};
    data[16] = 0x00;
    data[17] = BGP_OPEN_MSG_MIN_LEN;
    data[18] = 0x01;

    uint16_t declared = 0;
    size_t frame = 0;
    CHECK(bgp::getMessageFrame(data.data(), data.size(), declared, frame));
    CHECK(declared == BGP_OPEN_MSG_MIN_LEN);
    CHECK(frame == BGP_OPEN_MSG_MIN_LEN);

    // Declared length shorter than the buffer is honored
    data[17] = BGP_MSG_HDR_LEN + 2;
    CHECK(bgp::getMessageFrame(data.data(), data.size(), declared, frame));
    CHECK(frame == BGP_MSG_HDR_LEN + 2);

    // Declared length below the header size is clamped to the buffer
    data[17] = BGP_MSG_HDR_LEN - 1;
    CHECK(bgp::getMessageFrame(data.data(), data.size(), declared, frame));
    CHECK(declared == BGP_MSG_HDR_LEN - 1);
    CHECK(frame == data.size());

    // Declared length beyond the buffer is clamped to the buffer
    data[16] = 0xFF;
    data[17] = 0xFF;
    CHECK(bgp::getMessageFrame(data.data(), data.size(), declared, frame));
    CHECK(declared == 0xFFFF);
    CHECK(frame == data.size());

    CHECK(!bgp::getMessageFrame(data.data(), BGP_MSG_HDR_LEN - 1, declared, frame));
    CHECK(!bgp::getMessageFrame(nullptr, data.size(), declared, frame));
}

void testOpenParametersStandardFormat() {
    bgp::OpenParamsView view = {};
    const unsigned char empty_parameters[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 0
    };
    CHECK(bgp::locateOpenParameters(empty_parameters, sizeof(empty_parameters), view));
    CHECK(!view.extended);
    CHECK(!view.truncated);
    CHECK(view.length == 0);

    CHECK(!bgp::locateOpenParameters(empty_parameters, sizeof(empty_parameters) - 1, view));
    CHECK(!bgp::locateOpenParameters(nullptr, sizeof(empty_parameters), view));

    const unsigned char parameters[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 8,
        2, 6, 65, 4, 0, 0, 0xFD, 0xE9
    };
    CHECK(bgp::locateOpenParameters(parameters, sizeof(parameters), view));
    CHECK(!view.extended);
    CHECK(!view.truncated);
    CHECK(view.data == parameters + 10);
    CHECK(view.length == 8);

    // Declared parameter length beyond the message is clamped and flagged
    CHECK(bgp::locateOpenParameters(parameters, sizeof(parameters) - 3, view));
    CHECK(view.truncated);
    CHECK(view.length == 5);

    // param_len 255 without the RFC 9072 marker is a standard encoding
    std::vector<unsigned char> long_standard(10 + 255, 0);
    long_standard[9] = 255;
    long_standard[10] = 2;
    CHECK(bgp::locateOpenParameters(long_standard.data(), long_standard.size(), view));
    CHECK(!view.extended);
    CHECK(!view.truncated);
    CHECK(view.length == 255);
}

void testOpenParametersExtendedFormat() {
    bgp::OpenParamsView view = {};
    const unsigned char extended[] = {
        4, 0, 1, 0, 90, 192, 0, 2, 1, 255,
        255, 0, 9,
        2, 0, 6, 65, 4, 0, 0, 0xFD, 0xE9
    };
    CHECK(bgp::locateOpenParameters(extended, sizeof(extended), view));
    CHECK(view.extended);
    CHECK(!view.truncated);
    CHECK(view.data == extended + 13);
    CHECK(view.length == 9);

    bgp::OpenElementCursor params(view.data, view.length, view.extended);
    bgp::OpenElement param = {};
    CHECK(params.next(param) == bgp::OpenReadResult::OK);
    CHECK(param.type == 2);
    CHECK(param.length == 6);
    CHECK(params.next(param) == bgp::OpenReadResult::END);

    bgp::OpenElementCursor caps(param.value, param.length, false);
    bgp::OpenElement cap = {};
    CHECK(caps.next(cap) == bgp::OpenReadResult::OK);
    CHECK(cap.type == 65);
    CHECK(cap.length == 4);
    CHECK(cap.value[3] == 0xE9);
    CHECK(caps.next(cap) == bgp::OpenReadResult::END);

    // Extended header itself truncated
    CHECK(bgp::locateOpenParameters(extended, 12, view));
    CHECK(view.extended);
    CHECK(view.truncated);
    CHECK(view.length == 0);

    // Extended length larger than message is clamped
    CHECK(bgp::locateOpenParameters(extended, sizeof(extended) - 2, view));
    CHECK(view.extended);
    CHECK(view.truncated);
    CHECK(view.length == 7);

    // Extended parameters larger than 255 bytes
    const size_t caps_len = 300;
    std::vector<unsigned char> big = {4, 0, 1, 0, 90, 192, 0, 2, 1, 255, 255, 0x01, 0x2F};
    big.push_back(2);
    big.push_back(static_cast<unsigned char>(caps_len >> 8));
    big.push_back(static_cast<unsigned char>(caps_len & 0xFF));
    for (size_t i = 0; i < caps_len / 6; ++i) {
        const unsigned char mp[] = {1, 4, 0, 1, 0, 1};
        big.insert(big.end(), mp, mp + sizeof(mp));
    }
    CHECK(big.size() == 13 + 3 + caps_len);
    CHECK(bgp::locateOpenParameters(big.data(), big.size(), view));
    CHECK(view.extended);
    CHECK(!view.truncated);
    CHECK(view.length == caps_len + 3);

    bgp::OpenElementCursor big_params(view.data, view.length, true);
    CHECK(big_params.next(param) == bgp::OpenReadResult::OK);
    CHECK(param.length == caps_len);
    CHECK(big_params.next(param) == bgp::OpenReadResult::END);

    size_t count = 0;
    bgp::OpenElementCursor big_caps(param.value, param.length, false);
    while (big_caps.next(cap) == bgp::OpenReadResult::OK)
        ++count;
    CHECK(count == caps_len / 6);
}

void testOpenElementCursorTruncation() {
    bgp::OpenElement element = {};

    const unsigned char one_byte[] = {2};
    bgp::OpenElementCursor short_header(one_byte, sizeof(one_byte), false);
    CHECK(short_header.next(element) == bgp::OpenReadResult::TRUNCATED);

    const unsigned char two_bytes[] = {2, 0};
    bgp::OpenElementCursor short_extended(two_bytes, sizeof(two_bytes), true);
    CHECK(short_extended.next(element) == bgp::OpenReadResult::TRUNCATED);

    const unsigned char long_value[] = {2, 5, 1, 4, 0};
    bgp::OpenElementCursor long_element(long_value, sizeof(long_value), false);
    CHECK(long_element.next(element) == bgp::OpenReadResult::TRUNCATED);

    const unsigned char good_then_bad[] = {70, 0, 65, 4, 0, 0};
    bgp::OpenElementCursor mixed(good_then_bad, sizeof(good_then_bad), false);
    CHECK(mixed.next(element) == bgp::OpenReadResult::OK);
    CHECK(element.type == 70);
    CHECK(element.length == 0);
    CHECK(mixed.next(element) == bgp::OpenReadResult::TRUNCATED);

    bgp::OpenElementCursor empty(nullptr, 0, false);
    CHECK(empty.next(element) == bgp::OpenReadResult::END);
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
    testBgpMessageFrame();
    testOpenParametersStandardFormat();
    testOpenParametersExtendedFormat();
    testOpenElementCursorTruncation();
    return 0;
}
