/*
 * Handler-level regression tests for BMP TLV and BGP OPEN parsing.
 *
 * These tests drive the production parseBMP, OpenMsg, and parseBGP code with
 * crafted wire data, including the F083 malformed TLV inputs.
 */
#include "parseBMP.h"
#include "parseBGP.h"
#include "OpenMsg.h"
#include "Logger.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#define CHECK(condition) do { if (!(condition)) { std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); std::abort(); } } while (false)

namespace {

typedef std::vector<unsigned char> Bytes;

Logger *logger() {
    static Logger instance(NULL, NULL);
    return &instance;
}

void put16(Bytes &out, size_t value) {
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
    out.push_back(static_cast<unsigned char>(value & 0xFF));
}

void putTlv(Bytes &out, uint16_t type, const Bytes &value, size_t declared_len) {
    put16(out, type);
    put16(out, declared_len);
    out.insert(out.end(), value.begin(), value.end());
}

void putTlv(Bytes &out, uint16_t type, const Bytes &value) {
    putTlv(out, type, value, value.size());
}

Bytes text(const std::string &value) {
    return Bytes(value.begin(), value.end());
}

Bytes bmpMessage(unsigned char type, const Bytes &body) {
    Bytes msg;
    size_t total = 6 + body.size();
    msg.push_back(3);
    msg.push_back(static_cast<unsigned char>((total >> 24) & 0xFF));
    msg.push_back(static_cast<unsigned char>((total >> 16) & 0xFF));
    msg.push_back(static_cast<unsigned char>((total >> 8) & 0xFF));
    msg.push_back(static_cast<unsigned char>(total & 0xFF));
    msg.push_back(type);
    msg.insert(msg.end(), body.begin(), body.end());
    return msg;
}

class SocketPair {
public:
    SocketPair() {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        int buf = 256 * 1024;
        setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    }

    ~SocketPair() {
        close(fds[0]);
        close(fds[1]);
    }

    void send(const Bytes &data) {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t rc = write(fds[0], data.data() + sent, data.size() - sent);
            CHECK(rc > 0);
            sent += static_cast<size_t>(rc);
        }
    }

    int reader() const {
        return fds[1];
    }

private:
    int fds[2];
};

struct BmpHarness {
    MsgBusInterface::obj_bgp_peer peer;
    MsgBusInterface::obj_router router;
    parseBMP *parser;

    BmpHarness() {
        parser = new parseBMP(logger(), &peer);
        memset(&router, 0, sizeof(router));
    }

    ~BmpHarness() {
        delete parser;
    }

    void runInit(const Bytes &body) {
        SocketPair sock;
        sock.send(bmpMessage(parseBMP::TYPE_INIT_MSG, body));
        CHECK(parser->handleMessage(sock.reader()) == parseBMP::TYPE_INIT_MSG);
        parser->handleInitMsg(sock.reader(), router);
    }

    void runTerm(const Bytes &body) {
        SocketPair sock;
        sock.send(bmpMessage(parseBMP::TYPE_TERM_MSG, body));
        CHECK(parser->handleMessage(sock.reader()) == parseBMP::TYPE_TERM_MSG);
        parser->handleTermMsg(sock.reader(), router);
    }
};

// ---------------------------------------------------------------------------
// BMP Initiation
// ---------------------------------------------------------------------------

void testInitZeroLengthFreeFormString() {
    // F083 PoC: INIT_TYPE_FREE_FORM_STRING with length 0
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_FREE_FORM_STRING, Bytes());
    h.runInit(body);
    CHECK(h.router.initiate_data[0] == '\0');
    CHECK(h.router.hash_type == 0);
}

void testInitZeroLengthAllTypes() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_FREE_FORM_STRING, Bytes());
    putTlv(body, parseBMP::INIT_TYPE_SYSDESCR, Bytes());
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, Bytes());
    putTlv(body, parseBMP::INIT_TYPE_ROUTER_BGP_ID, Bytes());
    putTlv(body, 0x7777, Bytes());
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("router1"));
    h.runInit(body);
    CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "router1");
    CHECK(h.router.descr[0] == '\0');
    CHECK(h.router.bgp_id[0] == '\0');
    CHECK(h.router.hash_type == 1);
}

void testInitNormalValues() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_FREE_FORM_STRING, text("hello"));
    putTlv(body, parseBMP::INIT_TYPE_SYSDESCR, text("SONiC"));
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("sonic-1"));
    putTlv(body, parseBMP::INIT_TYPE_ROUTER_BGP_ID, Bytes{10, 1, 2, 3});
    h.runInit(body);
    CHECK(std::string(h.router.initiate_data) == "hello");
    CHECK(std::string(reinterpret_cast<char *>(h.router.descr)) == "SONiC");
    CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "sonic-1");
    CHECK(std::string(h.router.bgp_id) == "10.1.2.3");
    CHECK(h.router.hash_type == 2);
}

void testInitOversizedValuesAreBounded() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_FREE_FORM_STRING, Bytes(5000, 'f'));
    putTlv(body, parseBMP::INIT_TYPE_SYSDESCR, Bytes(300, 'd'));
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, Bytes(255, 'n'));
    putTlv(body, parseBMP::INIT_TYPE_SYSDESCR + 100, Bytes(10, 'x'));
    h.runInit(body);
    CHECK(strlen(h.router.initiate_data) == sizeof(h.router.initiate_data) - 1);
    CHECK(strnlen(reinterpret_cast<char *>(h.router.descr), sizeof(h.router.descr)) == sizeof(h.router.descr) - 1);
    CHECK(strnlen(reinterpret_cast<char *>(h.router.name), sizeof(h.router.name)) == sizeof(h.router.name) - 1);
    CHECK(h.router.ip_addr[0] == '\0');
}

void testInitDuplicateStringHasNoStaleSuffix() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("long-router-name"));
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("r2"));
    h.runInit(body);
    CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "r2");
}

void testInitInvalidBgpIdLengthIgnored() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::INIT_TYPE_ROUTER_BGP_ID, Bytes{1, 2, 3});
    putTlv(body, parseBMP::INIT_TYPE_ROUTER_BGP_ID, Bytes{1, 2, 3, 4, 5});
    putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("after"));
    h.runInit(body);
    CHECK(h.router.bgp_id[0] == '\0');
    CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "after");
    CHECK(h.router.hash_type == 1);
}

void testInitTruncatedTlvKeepsParsedFields() {
    {
        BmpHarness h;
        Bytes body;
        putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("kept"));
        putTlv(body, parseBMP::INIT_TYPE_SYSDESCR, text("abc"), 0xFFFF);
        h.runInit(body);
        CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "kept");
        CHECK(h.router.descr[0] == '\0');
    }
    {
        BmpHarness h;
        Bytes body;
        putTlv(body, parseBMP::INIT_TYPE_SYSNAME, text("kept"));
        body.push_back(0);
        body.push_back(1);
        body.push_back(0);
        h.runInit(body);
        CHECK(std::string(reinterpret_cast<char *>(h.router.name)) == "kept");
    }
}

// ---------------------------------------------------------------------------
// BMP Termination
// ---------------------------------------------------------------------------

void testTermZeroLengthTlvs() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::TERM_TYPE_FREE_FORM_STRING, Bytes());
    putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes());
    h.runTerm(body);
    CHECK(h.router.term_data[0] == '\0');
    CHECK(h.router.term_reason_code == 0);
    CHECK(h.router.term_reason_text[0] == '\0');
}

void testTermNormalValues() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::TERM_TYPE_FREE_FORM_STRING, text("bye"));
    putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes{0, parseBMP::TERM_REASON_OUT_OF_RESOURCES});
    h.runTerm(body);
    CHECK(std::string(h.router.term_data) == "bye");
    CHECK(h.router.term_reason_code == parseBMP::TERM_REASON_OUT_OF_RESOURCES);
    CHECK(std::string(h.router.term_reason_text) == "Remote out of resources");
}

void testTermOversizedStringIsBounded() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::TERM_TYPE_FREE_FORM_STRING, Bytes(65000, 't'));
    putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes{0, parseBMP::TERM_REASON_ADMIN_CLOSE});
    h.runTerm(body);
    CHECK(strlen(h.router.term_data) == sizeof(h.router.term_data) - 1);
    CHECK(h.router.timestamp_secs == 0);
    CHECK(h.router.term_reason_code == parseBMP::TERM_REASON_ADMIN_CLOSE);
}

void testTermReasonLengthHandling() {
    {
        BmpHarness h;
        Bytes body;
        putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes{0});
        h.runTerm(body);
        CHECK(h.router.term_reason_code == 0);
        CHECK(h.router.term_reason_text[0] == '\0');
    }
    {
        BmpHarness h;
        Bytes body;
        putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes{0, parseBMP::TERM_REASON_REDUNDANT_CONN, 9});
        h.runTerm(body);
        CHECK(h.router.term_reason_code == parseBMP::TERM_REASON_REDUNDANT_CONN);
    }
}

void testTermTruncatedTlv() {
    BmpHarness h;
    Bytes body;
    putTlv(body, parseBMP::TERM_TYPE_FREE_FORM_STRING, text("before"));
    putTlv(body, parseBMP::TERM_TYPE_REASON, Bytes{0}, 2);
    h.runTerm(body);
    CHECK(std::string(h.router.term_data) == "before");
    CHECK(h.router.term_reason_code == 0);
}

// ---------------------------------------------------------------------------
// BMP Peer Up information TLVs
// ---------------------------------------------------------------------------

void testPeerUpInfo() {
    {
        // Zero-length VRF/table name: previously copied from NULL
        BmpHarness h;
        Bytes info;
        putTlv(info, parseBMP::INFO_TLV_PEER_VRF_TABLE, Bytes());
        h.parser->parsePeerUpInfo(info.data(), static_cast<int>(info.size()));
        CHECK(h.peer.table_name[0] == '\0');
    }
    {
        BmpHarness h;
        Bytes info;
        putTlv(info, 0, text("ignored"));
        putTlv(info, parseBMP::INFO_TLV_PEER_VRF_TABLE, text("Vrf-red"));
        h.parser->parsePeerUpInfo(info.data(), static_cast<int>(info.size()));
        CHECK(std::string(reinterpret_cast<char *>(h.peer.table_name)) == "Vrf-red");
    }
    {
        BmpHarness h;
        Bytes info;
        putTlv(info, parseBMP::INFO_TLV_PEER_VRF_TABLE, Bytes(400, 'v'));
        h.parser->parsePeerUpInfo(info.data(), static_cast<int>(info.size()));
        CHECK(strnlen(reinterpret_cast<char *>(h.peer.table_name), sizeof(h.peer.table_name)) == sizeof(h.peer.table_name) - 1);
    }
    {
        BmpHarness h;
        Bytes info;
        putTlv(info, parseBMP::INFO_TLV_PEER_VRF_TABLE, text("Vrf"), 100);
        h.parser->parsePeerUpInfo(info.data(), static_cast<int>(info.size()));
        CHECK(h.peer.table_name[0] == '\0');

        Bytes short_header = {0, 3, 0};
        h.parser->parsePeerUpInfo(short_header.data(), static_cast<int>(short_header.size()));
        h.parser->parsePeerUpInfo(short_header.data(), 0);
        CHECK(h.peer.table_name[0] == '\0');
    }
}

// ---------------------------------------------------------------------------
// BGP OPEN
// ---------------------------------------------------------------------------

Bytes openPayload(const Bytes &params, bool extended) {
    Bytes out = {4, 0xFD, 0xE8, 0, 180, 10, 0, 0, 1};
    if (extended) {
        out.push_back(255);
        out.push_back(255);
        put16(out, params.size());
    } else {
        out.push_back(static_cast<unsigned char>(params.size()));
    }
    out.insert(out.end(), params.begin(), params.end());
    return out;
}

void putCapParam(Bytes &params, const Bytes &caps, bool extended) {
    params.push_back(2);
    if (extended)
        put16(params, caps.size());
    else
        params.push_back(static_cast<unsigned char>(caps.size()));
    params.insert(params.end(), caps.begin(), caps.end());
}

Bytes standardCaps() {
    return Bytes{
        1, 4, 0, 1, 0, 1,                // MPBGP IPv4 unicast
        2, 0,                            // Route refresh
        65, 4, 0, 0, 0xFD, 0xE9,         // 4-octet ASN 65001
        69, 4, 0, 1, 1, 3                // Add-Path IPv4 unicast send/receive
    };
}

struct OpenResult {
    size_t read;
    uint32_t asn;
    uint16_t hold;
    std::string bgp_id;
    std::list<std::string> caps;
    BMPReader::peer_info info;
};

void runOpen(Bytes payload, OpenResult &r, bool sent = true) {
    r.asn = 0;
    r.hold = 0;
    bgp_msg::OpenMsg msg(logger(), "192.0.2.1", &r.info);
    r.read = msg.parseOpenMsg(payload.data(), payload.size(), sent, r.asn, r.hold, r.bgp_id, r.caps);
}

bool hasCap(const OpenResult &r, const std::string &prefix) {
    for (std::list<std::string>::const_iterator it = r.caps.begin(); it != r.caps.end(); ++it)
        if (it->find(prefix) == 0)
            return true;
    return false;
}

void testOpenStandard() {
    Bytes params;
    putCapParam(params, standardCaps(), false);
    Bytes payload = openPayload(params, false);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == payload.size());
    CHECK(r.asn == 65001);
    CHECK(r.hold == 180);
    CHECK(r.bgp_id == "10.0.0.1");
    CHECK(hasCap(r, "4 Octet ASN"));
    CHECK(hasCap(r, "MPBGP"));
    CHECK(hasCap(r, "ADD Path"));
}

void testOpenNoParameters() {
    Bytes payload = openPayload(Bytes(), false);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == payload.size());
    CHECK(r.caps.empty());
}

void testOpenRfc9072Extended() {
    // Small extended encoding
    {
        Bytes params;
        putCapParam(params, standardCaps(), true);
        Bytes payload = openPayload(params, true);
        OpenResult r;
        runOpen(payload, r);
        CHECK(r.read == payload.size());
        CHECK(r.asn == 65001);
        CHECK(hasCap(r, "4 Octet ASN"));
        CHECK(hasCap(r, "MPBGP"));
    }
    // Extended encoding with more than 255 bytes of capabilities (FRR behavior)
    {
        Bytes caps = standardCaps();
        while (caps.size() < 400) {
            const unsigned char unknown[] = {200, 8, 1, 2, 3, 4, 5, 6, 7, 8};
            caps.insert(caps.end(), unknown, unknown + sizeof(unknown));
        }
        Bytes params;
        putCapParam(params, caps, true);
        Bytes payload = openPayload(params, true);
        OpenResult r;
        runOpen(payload, r);
        CHECK(r.read == payload.size());
        CHECK(r.asn == 65001);
        CHECK(hasCap(r, "4 Octet ASN"));
        CHECK(hasCap(r, "200"));
    }
}

void testOpenTruncatedParametersTolerated() {
    // A complete first parameter is parsed; the truncated second parameter is skipped (baseline behavior)
    Bytes params;
    putCapParam(params, Bytes{65, 4, 0, 0, 0xFD, 0xE9}, false);
    putCapParam(params, Bytes{1, 4, 0, 1, 0, 1}, false);
    Bytes payload = openPayload(params, false);
    payload.resize(payload.size() - 3);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == payload.size());
    CHECK(r.asn == 65001);
    CHECK(hasCap(r, "4 Octet ASN"));
    CHECK(!hasCap(r, "MPBGP"));

    // Only a truncated parameter: header ASN is kept and the OPEN is still accepted
    Bytes single;
    putCapParam(single, standardCaps(), false);
    payload = openPayload(single, false);
    payload.resize(payload.size() - 3);
    OpenResult r2;
    runOpen(payload, r2);
    CHECK(r2.read == payload.size());
    CHECK(r2.asn == 65000);
    CHECK(r2.caps.empty());
}

void testOpenMalformedCapabilitiesSkipped() {
    // Capability length exceeds its parameter; a later valid parameter is still parsed
    Bytes params = {2, 3, 65, 9, 0};
    putCapParam(params, Bytes{65, 4, 0, 0, 0xFD, 0xEA}, false);
    params.push_back(1);                            // unsupported parameter type
    params.push_back(2);
    params.push_back(0);
    params.push_back(0);
    Bytes payload = openPayload(params, false);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == payload.size());
    CHECK(r.asn == 65002);

    // Optional parameter length overruns the declared optional parameters
    Bytes overrun = {2, 50, 65, 4, 0, 0, 0xFD, 0xEB};
    payload = openPayload(overrun, false);
    OpenResult r2;
    runOpen(payload, r2);
    CHECK(r2.read == payload.size());
    CHECK(r2.asn == 65000);
    CHECK(r2.caps.empty());
}

void testOpenAddPathPartialTuple() {
    Bytes params;
    putCapParam(params, Bytes{69, 6, 0, 1, 1, 3, 0, 2}, false);
    Bytes payload = openPayload(params, false);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == payload.size());
    CHECK(hasCap(r, "ADD Path"));

    // Following capability must still be parsed (no double advance)
    Bytes params2;
    putCapParam(params2, Bytes{69, 8, 0, 1, 1, 3, 0, 2, 1, 1, 65, 4, 0, 0, 0xFD, 0xEC}, false);
    payload = openPayload(params2, false);
    OpenResult r2;
    runOpen(payload, r2);
    CHECK(r2.read == payload.size());
    CHECK(r2.asn == 65004);
}

void testOpenInvalidMpbgpRejectedAsBaseline() {
    Bytes params;
    putCapParam(params, Bytes{1, 3, 0, 1, 0}, false);
    Bytes payload = openPayload(params, false);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == 0);
}

void testOpenTooShort() {
    Bytes payload = openPayload(Bytes(), false);
    payload.resize(9);
    OpenResult r;
    runOpen(payload, r);
    CHECK(r.read == 0);
}

// ---------------------------------------------------------------------------
// BGP framing via parseBGP
// ---------------------------------------------------------------------------

Bytes bgpMessage(unsigned char type, const Bytes &payload, size_t declared_len) {
    Bytes out(16, 0xFF);
    put16(out, declared_len);
    out.push_back(type);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Bytes bgpMessage(unsigned char type, const Bytes &payload) {
    return bgpMessage(type, payload, 19 + payload.size());
}

struct BgpHarness {
    MsgBusInterface::obj_bgp_peer peer;
    BMPReader::peer_info info;
    MsgBusInterface::obj_peer_up_event up;
    parseBGP *parser;

    BgpHarness() {
        memset(&peer, 0, sizeof(peer));
        memset(&up, 0, sizeof(up));
        strcpy(peer.peer_addr, "192.0.2.1");
        parser = new parseBGP(logger(), NULL, &peer, "198.51.100.1", &info);
    }

    ~BgpHarness() {
        delete parser;
    }
};

void testUpEventStandardAndExtended() {
    Bytes params;
    putCapParam(params, standardCaps(), false);
    Bytes sent = bgpMessage(parseBGP::BGP_MSG_OPEN, openPayload(params, false));

    Bytes caps = standardCaps();
    while (caps.size() < 300)
        caps.insert(caps.end(), {201, 2, 0, 0});
    Bytes ext_params;
    putCapParam(ext_params, caps, true);
    Bytes recv = bgpMessage(parseBGP::BGP_MSG_OPEN, openPayload(ext_params, true));

    Bytes info;
    putTlv(info, parseBMP::INFO_TLV_PEER_VRF_TABLE, text("default"));

    Bytes data = sent;
    data.insert(data.end(), recv.begin(), recv.end());
    data.insert(data.end(), info.begin(), info.end());

    BgpHarness h;
    int read = h.parser->handleUpEvent(data.data(), data.size(), &h.up);
    CHECK(read == static_cast<int>(sent.size() + recv.size()));
    CHECK(h.up.local_asn == 65001);
    CHECK(h.up.remote_asn == 65001);
    CHECK(std::string(h.up.local_bgp_id) == "10.0.0.1");
    CHECK(std::string(h.up.recv_cap).find("201") != std::string::npos);
    CHECK(h.info.sent_four_octet_asn);
    CHECK(h.info.recv_four_octet_asn);
}

void testUpEventTruncatedReceivedOpen() {
    Bytes params;
    putCapParam(params, standardCaps(), false);
    Bytes sent = bgpMessage(parseBGP::BGP_MSG_OPEN, openPayload(params, false));
    Bytes recv_params;
    putCapParam(recv_params, Bytes{65, 4, 0, 0, 0xFD, 0xE9}, false);
    putCapParam(recv_params, Bytes{1, 4, 0, 1, 0, 1}, false);
    Bytes recv = bgpMessage(parseBGP::BGP_MSG_OPEN, openPayload(recv_params, false));
    // Received OPEN declares more bytes than the BMP message carries
    recv.resize(recv.size() - 4);

    Bytes data = sent;
    data.insert(data.end(), recv.begin(), recv.end());

    BgpHarness h;
    int read = h.parser->handleUpEvent(data.data(), data.size(), &h.up);
    CHECK(read == static_cast<int>(data.size()));
    CHECK(h.up.remote_asn == 65001);
}

void testUpEventRejectsShortOpen() {
    Bytes short_open = bgpMessage(parseBGP::BGP_MSG_OPEN, Bytes(10, 0), 28);
    BgpHarness h;
    bool threw = false;
    try {
        h.parser->handleUpEvent(short_open.data(), short_open.size(), &h.up);
    } catch (const char *) {
        threw = true;
    }
    CHECK(threw);

    Bytes not_open = bgpMessage(parseBGP::BGP_MSG_UPDATE, Bytes(10, 0));
    threw = false;
    try {
        h.parser->handleUpEvent(not_open.data(), not_open.size(), &h.up);
    } catch (const char *) {
        threw = true;
    }
    CHECK(threw);
}

void testUpdateLengthMismatchSkipped() {
    Bytes update = bgpMessage(parseBGP::BGP_MSG_UPDATE, Bytes{0, 0, 0, 0}, 0xFFFF);
    BgpHarness h;
    CHECK(h.parser->handleUpdate(update.data(), update.size()));

    Bytes tiny = bgpMessage(parseBGP::BGP_MSG_UPDATE, Bytes{0, 0, 0, 0}, 5);
    CHECK(h.parser->handleUpdate(tiny.data(), tiny.size()));
}

void testDownEventLengthMismatchTolerated() {
    Bytes notify = bgpMessage(parseBGP::BGP_MSG_NOTIFICATION, Bytes{6, 2}, 0xFFFF);
    BgpHarness h;
    MsgBusInterface::obj_peer_down_event down;
    memset(&down, 0, sizeof(down));
    h.parser->handleDownEvent(notify.data(), notify.size(), down);
    CHECK(down.bgp_err_code == 6);
    CHECK(down.bgp_err_subcode == 2);
}

void testDownEventShortNotificationRejected() {
    for (size_t body_len = 0; body_len < 2; ++body_len) {
        Bytes notify = bgpMessage(parseBGP::BGP_MSG_NOTIFICATION, Bytes(body_len, 6));
        BgpHarness h;
        MsgBusInterface::obj_peer_down_event down;
        memset(&down, 0, sizeof(down));
        CHECK(h.parser->handleDownEvent(notify.data(), notify.size(), down));
        CHECK(down.bgp_err_code == 0);
        CHECK(down.bgp_err_subcode == 0);
    }
}

} // namespace

int main(int argc, char **argv) {
    struct TestCase {
        const char *name;
        void (*run)();
    };

    const TestCase tests[] = {
        {"testInitZeroLengthFreeFormString", testInitZeroLengthFreeFormString},
        {"testInitZeroLengthAllTypes", testInitZeroLengthAllTypes},
        {"testInitNormalValues", testInitNormalValues},
        {"testInitOversizedValuesAreBounded", testInitOversizedValuesAreBounded},
        {"testInitDuplicateStringHasNoStaleSuffix", testInitDuplicateStringHasNoStaleSuffix},
        {"testInitInvalidBgpIdLengthIgnored", testInitInvalidBgpIdLengthIgnored},
        {"testInitTruncatedTlvKeepsParsedFields", testInitTruncatedTlvKeepsParsedFields},
        {"testTermZeroLengthTlvs", testTermZeroLengthTlvs},
        {"testTermNormalValues", testTermNormalValues},
        {"testTermOversizedStringIsBounded", testTermOversizedStringIsBounded},
        {"testTermReasonLengthHandling", testTermReasonLengthHandling},
        {"testTermTruncatedTlv", testTermTruncatedTlv},
        {"testPeerUpInfo", testPeerUpInfo},
        {"testOpenStandard", testOpenStandard},
        {"testOpenNoParameters", testOpenNoParameters},
        {"testOpenRfc9072Extended", testOpenRfc9072Extended},
        {"testOpenTruncatedParametersTolerated", testOpenTruncatedParametersTolerated},
        {"testOpenMalformedCapabilitiesSkipped", testOpenMalformedCapabilitiesSkipped},
        {"testOpenAddPathPartialTuple", testOpenAddPathPartialTuple},
        {"testOpenInvalidMpbgpRejectedAsBaseline", testOpenInvalidMpbgpRejectedAsBaseline},
        {"testOpenTooShort", testOpenTooShort},
        {"testUpEventStandardAndExtended", testUpEventStandardAndExtended},
        {"testUpEventTruncatedReceivedOpen", testUpEventTruncatedReceivedOpen},
        {"testUpEventRejectsShortOpen", testUpEventRejectsShortOpen},
        {"testUpdateLengthMismatchSkipped", testUpdateLengthMismatchSkipped},
        {"testDownEventLengthMismatchTolerated", testDownEventLengthMismatchTolerated},
        {"testDownEventShortNotificationRejected", testDownEventShortNotificationRejected},
    };

    size_t executed = 0;
    for (const TestCase &test : tests) {
        if (argc > 1 && strcmp(argv[1], test.name) != 0)
            continue;
        std::printf("RUN  %s\n", test.name);
        std::fflush(stdout);
        test.run();
        ++executed;
    }

    CHECK(executed > 0);
    std::printf("All %zu BMP handler tests passed\n", executed);
    return 0;
}
