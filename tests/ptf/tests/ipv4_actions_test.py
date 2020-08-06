import subprocess
from ptf.mask import Mask
from ptf.packet import TCP, IP, Ether
from ptf import config, testutils
import time
from ptf.testutils import send_packet, verify_packets, simple_ip_packet
from p4runtime_test import ipv4_to_binary, stringify, autocleanup
from p4runtime_test import P4RuntimeTest

INITIALIZED = False

class Ipv4Test(P4RuntimeTest):

    def init_port_fwd(self):
        self.send_request_add_entry_to_action(
            "fwd_tbl",
            [self.Exact("std_meta.input_port", stringify(33, 4))],
            "fwd",
            [("port", stringify(34, 4))]
        )
        self.send_request_add_entry_to_action(
            "fwd_tbl",
            [self.Exact("std_meta.input_port", stringify(34, 4))],
            "fwd",
            [("port", stringify(33, 4))]
        )

    def setUp(self):
        params = testutils.test_params_get()
        params['p4info'] = "build/test-ipv4-actions.p4info.txt"
        P4RuntimeTest.setUp(self)
        global INITIALIZED
        if INITIALIZED:
            return

        success = self.update_config("build/test-ipv4-actions.o", "build/test-ipv4-actions.pb.txt")
        if not success:
            self.fail("P4 pipeline not configured.")

        INITIALIZED = True

    def tearDown(self):
        P4RuntimeTest.tearDown(self)


class Ipv4TTLTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr)

        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_ttl",
            [("ttl", stringify(5, 1))]
        )

        exp_pkt = pkt
        exp_pkt[IP].ttl = 5

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4DiffservTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr)


        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_diffserv",
            [("diffserv", stringify(1, 1))]
        )

        exp_pkt = pkt
        exp_pkt[IP].tos = 1

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4IdentificationTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr)


        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_identification",
            [("identification", stringify(11, 2))]
        )

        exp_pkt = pkt
        exp_pkt[IP].id = 0x000b

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4SetDstAddrTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr, ip_dst="10.0.0.2")
        exp_pkt = simple_ip_packet(ip_src=ip_src_addr, ip_dst="10.10.10.11")

        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_dstAddr",
            [("dstAddr", ipv4_to_binary("10.10.10.11"))]
        )

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4SetSrcDstAddrTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        exp_ip_src = "10.10.10.12"
        exp_ip_dst = "10.10.10.11"
        pkt = simple_ip_packet(ip_src="10.0.0.1", ip_dst="10.0.0.2")
        exp_pkt = simple_ip_packet(ip_src=exp_ip_src, ip_dst=exp_ip_dst)

        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_srcAddr_dstAddr",
            [("srcAddr", ipv4_to_binary(exp_ip_src)), ("dstAddr", ipv4_to_binary(exp_ip_dst))]
        )

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4SetVersionTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr)

        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_ipv4_version",
            [("version", stringify(6, 1))]
        )

        exp_pkt = pkt
        exp_pkt[IP].version = 6

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])


class Ipv4SetFlagsTTLTest(Ipv4Test):

    @autocleanup
    def runTest(self):
        self.init_port_fwd()
        ip_src_addr = "10.0.0.1"
        ip_src_addr_str = ipv4_to_binary(ip_src_addr)
        pkt = simple_ip_packet(ip_src=ip_src_addr)

        self.send_request_add_entry_to_action(
            "filter_tbl",
            [self.Exact("headers.ipv4.srcAddr", ip_src_addr_str)],
            "set_flags_ttl",
            [("flags", stringify(3, 1)), ("ttl", stringify(63, 1))]
        )

        exp_pkt = pkt
        exp_pkt[IP].flags = 3
        exp_pkt[IP].ttl = 63

        mask = Mask(exp_pkt)
        mask.set_do_not_care_scapy(IP, 'chksum')

        send_packet(self, 0, pkt)
        verify_packets(self, mask, device_number=0, ports=[1])