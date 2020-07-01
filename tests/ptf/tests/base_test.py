import subprocess
from p4runtime_test import P4RuntimeTest
from ptf.base_tests import BaseTest
from ptf import config, testutils
import ptf
import os

class P4OvSBaseTest(P4RuntimeTest):

    def invoke_ovs_cmd(self, cmd=[]):
        print "Invoking OVS command: ", ' '.join(str(x) for x in cmd)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = proc.communicate()

        if output:
            print "Output: ", output

        if error:
            print "Error: ", error

        return output

    def clear_ovs(self):
        cmd_delbr = ['ovs-vsctl', 'del-br', self.bridge]
        self.invoke_ovs_cmd(cmd_delbr)

    def create_bridge_and_ports(self):
        self.clear_ovs()
        cmd_addbr = ['ovs-vsctl', 'add-br', self.bridge, '--', 'set', 'bridge', self.bridge, 'datapath_type=ubpf',
               'p4=true', 'other_config:device_id=' + str(self.device_id)]
        self.invoke_ovs_cmd(cmd_addbr)
        cmd_add_port1 = ['ovs-vsctl', 'add-port', self.bridge, 'veth1',  '--', 'set', 'Interface', 'veth1', 'ofport_request=1']
        cmd_add_port2 = ['ovs-vsctl', 'add-port', self.bridge, 'veth3',  '--', 'set', 'Interface', 'veth3', 'ofport_request=4']
        self.invoke_ovs_cmd(cmd_add_port1)
        self.invoke_ovs_cmd(cmd_add_port2)

    def setUp(self):
        P4RuntimeTest.setUp(self)
        self.bridge = "br0"
        self.create_bridge_and_ports()

    def tearDown(self):
        P4RuntimeTest.tearDown(self)
