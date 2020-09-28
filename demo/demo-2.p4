#include <core.p4>
#include <ubpf_model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32>     IPv4Address;

#define IPV4_ETHTYPE 0x800

// standard Ethernet header
header Ethernet_h
{
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16> etherType;
}

// IPv4 header without options
header IPv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
}

struct Headers_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
}

struct metadata {}


parser prs(packet_in packet, out Headers_t hdr, inout metadata meta, inout standard_metadata std_meta) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            IPV4_ETHTYPE: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control pipe(inout Headers_t hdr, inout metadata meta, inout standard_metadata std_meta) {

    action forward(bit<32> output) {
        std_meta.output_action = ubpf_action.REDIRECT;
        std_meta.output_port = output;
    }

    table test_tbl {

        key = {
            hdr.ethernet.srcAddr : exact;
        }

        actions = {
            forward();
            NoAction;
        }

        default_action = forward(2);

    }

    apply {
        test_tbl.apply();
    }

}

control dprs(packet_out packet, in Headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

ubpf(prs(), pipe(), dprs()) main;
