#! /usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
ovs-p4ctl utility allows to control P4 bridges.
"""

import argparse
import sys
import grpc
import logging
import json
import ovspy.client
import queue
import socket
import threading
import time
from functools import wraps

import google.protobuf.text_format
from google.rpc import status_pb2, code_pb2

from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc

# context = Context()

USAGE = "ovs-p4ctl: P4Runtime switch management utility\n" \
        "usage: ovs-p4ctl [OPTIONS] COMMAND [ARG...]\n" \
        "\nFor P4Runtime switches:\n" \
        "  show SWITCH                 show P4Runtime switch information\n" \
        "  set-pipe SWITCH PROGRAM P4INFO  set P4 pipeline for the swtich\n" \
        "  get-pipe SWITCH             get current P4 pipeline (P4Info) and print it\n" \
        "  dump-tables SWITCH          print table stats\n" \
        "  dump-table SWITCH TABLE     print table information\n"

def usage():
    print(USAGE)
    sys.exit(0)


class P4RuntimeErrorFormatException(Exception):
    def __init__(self, message):
        super().__init__(message)


# Used to iterate over the p4.Error messages in a gRPC error Status object
class P4RuntimeErrorIterator:
    def __init__(self, grpc_error):
        assert(grpc_error.code() == grpc.StatusCode.UNKNOWN)
        self.grpc_error = grpc_error

        error = None
        # The gRPC Python package does not have a convenient way to access the
        # binary details for the error: they are treated as trailing metadata.
        for meta in self.grpc_error.trailing_metadata():
            if meta[0] == "grpc-status-details-bin":
                error = status_pb2.Status()
                error.ParseFromString(meta[1])
                break
        if error is None:
            raise P4RuntimeErrorFormatException("No binary details field")

        if len(error.details) == 0:
            raise P4RuntimeErrorFormatException(
                "Binary details field has empty Any details repeated field")
        self.errors = error.details
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self.idx < len(self.errors):
            p4_error = p4runtime_pb2.Error()
            one_error_any = self.errors[self.idx]
            if not one_error_any.Unpack(p4_error):
                raise P4RuntimeErrorFormatException(
                    "Cannot convert Any message to p4.Error")
            if p4_error.canonical_code == code_pb2.OK:
                continue
            v = self.idx, p4_error
            self.idx += 1
            return v
        raise StopIteration


class P4RuntimeWriteException(Exception):
    def __init__(self, grpc_error):
        assert(grpc_error.code() == grpc.StatusCode.UNKNOWN)
        super().__init__()
        self.errors = []
        try:
            error_iterator = P4RuntimeErrorIterator(grpc_error)
            for error_tuple in error_iterator:
                self.errors.append(error_tuple)
        except P4RuntimeErrorFormatException:
            raise  # just propagate exception for now

    def __str__(self):
        message = "Error(s) during Write:\n"
        for idx, p4_error in self.errors:
            code_name = code_pb2._CODE.values_by_number[
                p4_error.canonical_code].name
            message += "\t* At index {}: {}, '{}'\n".format(
                idx, code_name, p4_error.message)
        return message


class P4RuntimeException(Exception):
    def __init__(self, grpc_error):
        super().__init__()
        self.grpc_error = grpc_error

    def __str__(self):
        message = "P4Runtime RPC error ({}): {}".format(
            self.grpc_error.code().name, self.grpc_error.details())
        return message

def parse_p4runtime_write_error(f):
    @wraps(f)
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNKNOWN:
                raise e
            raise P4RuntimeWriteException(e) from None
    return handle


def parse_p4runtime_error(f):
    @wraps(f)
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except grpc.RpcError as e:
            raise P4RuntimeException(e) from None
    return handle

class P4RuntimeClient:

    def __init__(self, device_id, grpc_addr='localhost:50051', election_id=(1, 0)):
        self.device_id = device_id
        self.election_id = election_id

        try:
            self.channel = grpc.insecure_channel(grpc_addr)
        except Exception as e:
            raise e
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.set_up_stream()

    def set_up_stream(self):
        self.stream_out_q = queue.Queue()
        self.stream_in_q = queue.Queue()

        def stream_req_iterator():
            while True:
                p = self.stream_out_q.get()
                if p is None:
                    break
                yield p

        def stream_recv_wrapper(stream):
            @parse_p4runtime_error
            def stream_recv():
                for p in stream:
                    self.stream_in_q.put(p)
            try:
                stream_recv()
            except P4RuntimeException as e:
                logging.critical("StreamChannel error, closing stream")
                logging.critical(e)
                self.stream_in_q.put(None)

        self.stream = self.stub.StreamChannel(stream_req_iterator())
        self.stream_recv_thread = threading.Thread(
            target=stream_recv_wrapper, args=(self.stream,))
        self.stream_recv_thread.start()

        self.handshake()

    def handshake(self):
        req = p4runtime_pb2.StreamMessageRequest()
        arbitration = req.arbitration
        arbitration.device_id = self.device_id
        election_id = arbitration.election_id
        election_id.high = self.election_id[0]
        election_id.low = self.election_id[1]
        self.stream_out_q.put(req)

        rep = self.get_stream_packet("arbitration", timeout=2)
        if rep is None:
            logging.critical("Failed to establish session with server")
            sys.exit(1)
        is_master = (rep.arbitration.status.code == code_pb2.OK)
        logging.debug("Session established, client is '{}'".format(
            'master' if is_master else 'slave'))
        if not is_master:
            print("You are not master, you only have read access to the server")

    def get_stream_packet(self, type_, timeout=1):
        start = time.time()
        try:
            while True:
                remaining = timeout - (time.time() - start)
                if remaining < 0:
                    break
                msg = self.stream_in_q.get(timeout=remaining)
                if msg is None:
                    return None
                if not msg.HasField(type_):
                    continue
                return msg
        except queue.Empty:  # timeout expired
            pass
        return None

    @parse_p4runtime_error
    def get_p4info(self):
        req = p4runtime_pb2.GetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.response_type = p4runtime_pb2.GetForwardingPipelineConfigRequest.P4INFO_AND_COOKIE
        rep = self.stub.GetForwardingPipelineConfig(req)
        return rep.config.p4info

    @parse_p4runtime_error
    def set_fwd_pipe_config(self, p4info_path, bin_path):
        req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        election_id = req.election_id
        election_id.high = self.election_id[0]
        election_id.low = self.election_id[1]
        req.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        with open(p4info_path, 'r') as f1:
            with open(bin_path, 'rb') as f2:
                try:
                    google.protobuf.text_format.Merge(f1.read(), req.config.p4info)
                except google.protobuf.text_format.ParseError:
                    logging.error("Error when parsing P4Info")
                    raise
                req.config.p4_device_config = f2.read()
        return self.stub.SetForwardingPipelineConfig(req)

    def tear_down(self):
        if self.stream_out_q:
            self.stream_out_q.put(None)
            self.stream_recv_thread.join()
        self.channel.close()
        del self.channel  # avoid a race condition if channel deleted when process terminates

    @parse_p4runtime_write_error
    def write(self, req):
        req.device_id = self.device_id
        election_id = req.election_id
        election_id.high = self.election_id[0]
        election_id.low = self.election_id[1]
        return self.stub.Write(req)

    @parse_p4runtime_write_error
    def write_update(self, update):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        election_id = req.election_id
        election_id.high = self.election_id[0]
        election_id.low = self.election_id[1]
        req.updates.extend([update])
        return self.stub.Write(req)


def resolve_device_id_by_bridge_name(bridge_name):
    ovs = ovspy.client.OvsClient(5000)

    if not ovs.find_bridge(bridge_name):
        raise Exception("bridge '{}' doesn't exist".format(bridge_name))

    for br in ovs.get_bridge_raw():
        if br['name'] == bridge_name:
            other_configs = br['other_config'][1][0]
            for i, cfg in enumerate(other_configs):
                if cfg == 'device_id':
                    return int(other_configs[i+1])
    # This function should not reach this line
    raise Exception("bridge '{}' does not have 'device_id' configured".format(bridge_name))

def with_client(f):
    @wraps(f)
    def handle(*args, **kwargs):
        client = None
        try:
            client = P4RuntimeClient(device_id=resolve_device_id_by_bridge_name(args[0]))
            f(client, *args, **kwargs)
        except Exception as e:
            raise e
        finally:
            if client:
                client.tear_down()
    return handle

@with_client
def p4ctl_set_pipe(client, bridge):
    if len(sys.argv) < 5:
        print("ovs-p4ctl: 'set-pipe' command requires at least 3 arguments")
        return

    device_config = sys.argv[3]
    p4info = sys.argv[4]

    client.set_fwd_pipe_config(p4info, device_config)

@with_client
def p4ctl_get_pipe(client, bridge):
    p4info = client.get_p4info()
    if p4info:
        print("P4Info of bridge {}:".format(bridge))
        print(p4info)

all_commands = {
    "set-pipe": p4ctl_set_pipe,
    "get-pipe": p4ctl_get_pipe,
}

def main():
    if len(sys.argv) < 2:
       print("ovs-p4ctl: missing command name; use --help for help")
       sys.exit(1)
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument('command', help='Subcommand to run')

    args = parser.parse_args(sys.argv[1:2])
    if not args.command in all_commands.keys():
        usage()

    bridge_name = sys.argv[2]
    try:
        # use dispatch pattern to invoke method with same name
        all_commands[args.command](bridge_name)
    except Exception as e:
        print("Error:", str(e))
        sys.exit(1)

if __name__ == '__main__':
    main()