/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_TRIANGLE = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

#define NUM_KEYS 16
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// NOTE: added new header type
header triangleFs_t {
    bit<16> proto_id;
    bit<16> dst_id;
    bit<16> is_new;
    bit<16> is_query;
    bit<16> is_delete;
    bit<32> packet_id;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
    bit is_master;
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t   ethernet;
    triangleFs_t triangle;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            TYPE_TRIANGLE : parse_triangle;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_triangle {
        packet.extract(hdr.triangle);
        transition select(hdr.triangle.proto_id) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit>(NUM_KEYS) forward_reg;
    register<bit>(NUM_KEYS) query_reg;
    bit forward_val;
    bit query_val;
    bit<32> curr_id; 

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action triangle_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action triangle_query_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action determine_master(bit is_master_b) {
        meta.is_master = is_master_b;
    }

    // Dst_id is always the same, this table is only used for
    // sending the packet to the next in the cycle
    table triangle_exact {
        key = {
            hdr.triangle.dst_id : exact;
        }
        actions = {
            triangle_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    // This table is filled so that the master forwards all
    // packets to the host, all others just forward in the cycle
    table triangle_query {
        key = {
            hdr.triangle.dst_id : exact;
        }
        actions = {
            triangle_query_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    table determine_master_exact {
        key = {
            hdr.triangle.dst_id : exact;
        }
        actions = {
            determine_master;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {


        if(hdr.triangle.isValid()) {
        
            determine_master_exact.apply();
            // if (hdr.triangle.isValid()) {
                // triangle_exact.apply();
                // if (meta.is_master == 1) {
                //     hdr.triangle.is_new = 3; 
                // } else {
                //     hdr.triangle.is_new = 4; 

                // }
            if (meta.is_master == 0) {
                triangle_exact.apply();
            } else {
                // We are on master switch
                // It is not a control packet
                if(hdr.triangle.is_delete == 0 && hdr.triangle.is_query == 0) {
                    if(hdr.triangle.is_new == 1) {
                        forward_reg.write(hdr.triangle.packet_id, 1);
                    }
                    forward_reg.read(forward_val, hdr.triangle.packet_id);
                    query_reg.read(query_val, hdr.triangle.packet_id);

                    if (query_val == 1) {
                        // if we are the master switch, forward to host
                        // otherwise just forward in the cycle
                        triangle_query.apply();
                    } else if (forward_val == 1) {
                        triangle_exact.apply();
                    } else {
                        mark_to_drop(standard_metadata);
                    }
                } else if (hdr.triangle.is_query == 1) {
                    query_reg.write(hdr.triangle.packet_id, 1);
                    forward_reg.write(hdr.triangle.packet_id, 0);
                    triangle_query.apply();
                } else if (hdr.triangle.is_delete == 1) {
                    forward_reg.write(hdr.triangle.packet_id, 0);
                }
            }
        } else if (hdr.ipv4.isValid()) {
                ipv4_lpm.apply();
                // debug: see that this part runs.
                triangle_query.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // TODO: emit myTunnel header as well
        packet.emit(hdr.triangle);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
