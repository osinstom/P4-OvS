## Join the discussion!

Join the [P4 Slack](https://p4-lang.slack.com) and look for **#p4-vswitch** channel, which is dedicated for discussion about this project!

## How to install? 

Please follow steps in [install.md](./install.md) to install P4-OVS. 

## How to use?

### Run demo yourself!

Make sure you have all required software (P4-OvS, p4c-ubpf, clang-6.0) installed. If not, please refer to the [installation guide](./install.md).

All the files needed to run this demo are located under `/demo` directory. Run all below commands from this directory.

The `demo.p4` P4 program is used to drive these demos. It does very simple, dumb forwarding between ports 1 and 4.

#### Demo #2 - Run P4-OvS with dynamically configured P4 program (via P4Runtime)

This demo shows how to run P4 bridge and configure P4 pipeline for a bridge using the P4Runtime control interface. 
As **ovs-p4ctl** is not implemented yet, we use [p4runtime-shell](https://github.com/p4lang/p4runtime-shell) as a P4Runtime client. 
Please install `p4runtime-shell` before moving on.

* Compile a P4 program with `p4c-ubpf` and option to generate P4Info file.

```bash
$ p4c-ubpf --arch ubpf -o demo.c --p4runtime-files demo.p4info.txt ./demo/demo.p4
```

* Compile from C to BPF:

```bash
$ clang-6.0 -O2 -target bpf -I../p4c/backends/ubpf/runtime -c demo.c -o demo.o
```

* Add OVS bridge of type "p4" without any initial P4 program configured:

```bash
$ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=ubpf p4=true
```

You should see the following message in the logs:

```bash
bridge|WARN|bridge br0: P4 target binary not provided. Initializing P4 datapath with no P4 program!
```

* Setup network namespaces and create `veth` interfaces. The `test.sh` script automates this step:

```bash
$ ./test.sh
```

* Attach ports to P4 bridge:

```bash
$ ovs-vsctl add-port br0 ovsp4-p0 -- set Interface ovsp4-p0 ofport_request=4
$ ovs-vsctl add-port br0 ovsp4-p1 -- set Interface ovsp4-p0 ofport_request=1
```

* Verify ports are added and no error occurred:

```bash
$ ovs-vsctl show
```

* You can run ``ping`` between namespaces, traffic should be **NOT** forwarded via P4 bridge as there is no P4 program installed yet:

```bash
$ ip netns exec ns0 ping -i .2 10.1.1.2
```

* Run `p4runtime-shell` to invoke SetForwardingPipelineConfig RPC. Note that address `172.17.0.1` is the IP address of `docker0`.

```bash
./p4runtime-sh-docker --grpc-addr 172.17.0.1:50051 --device-id 0 --config demo.p4info.txt,demo.o
```

You should see similar output as below:

```bash
DEBUG:root:Created temporary directory '/tmp/tmpn8a6drga', it will be mounted in the docker as '/fwd_pipe_config'
DEBUG:root:Running cmd: docker run -ti -v /tmp/tmpn8a6drga:/fwd_pipe_config p4lang/p4runtime-sh --verbose --config /fwd_pipe_config/p4info.pb.txt,/fwd_pipe_config/config.bin --grpc-addr 172.17.0.1:50051 --device-id 0
DEBUG:root:Creating P4Runtime client
DEBUG:root:Connecting to device 0 at 172.17.0.1:50051
DEBUG:root:Session established, client is 'master'
DEBUG:root:Setting forwarding pipeline config
DEBUG:root:Retrieving P4Info file
DEBUG:root:Parsing P4Info message
*** Welcome to the IPython shell for P4Runtime ***
P4Runtime sh >>>
```

* If you saw the above output it seems that P4 pipeline has been successfully configured! You should be able to run `ping` now:

```bash
$ ip netns exec ns0 ping -i .2 10.1.1.2
PING 10.1.1.2 (10.1.1.2) 56(84) bytes of data.
64 bytes from 10.1.1.2: icmp_seq=1 ttl=64 time=0.188 ms
64 bytes from 10.1.1.2: icmp_seq=2 ttl=64 time=0.299 ms
...
```

#### Demo #1 - Run P4-OvS with statically configured P4 program (via CLI)

* Compile the program with `p4c-ubpf` and generate P4Info:

```bash
$ p4c-ubpf --arch ubpf -o demo.c --p4runtime-files demo.p4info.txt demo-2.p4
```

* Compile from C to BPF:

```bash
$ clang-6.0 -O2 -target bpf -I../p4c/backends/ubpf/runtime -c demo.c -o demo.o
```

* For statically configured P4 program we need to convert P4Info file to match PI library restrictions. To do that
you should use `pi_convert_p4info` from PI library:

```bash
$ cd PI/proto/p4info
$ make
$ ./pi_convert_p4info -f prototext -t native -i <PATH TO demo.p4info.txt> -o demo.p4info.json
```

* Add OVS bridge of type "p4". You should provide `program` and `p4info`:

```bash
$ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=ubpf p4=true other_config:program="$(pwd)/demo/demo.o" \
            other_config:p4info=<PATH TO demo.p4info.json>
```

* Setup network namespaces and create `veth` interfaces. The `test.sh` script automates this step:

```bash
./test.sh
```

* Attach ports to P4 bridge:

```bash
$ ovs-vsctl add-port br0 ovsp4-p0 -- set Interface ovsp4-p0 ofport_request=4
$ ovs-vsctl add-port br0 ovsp4-p1 -- set Interface ovsp4-p0 ofport_request=1
```

* Verify ports are added and no error occurred:

```bash
$ ovs-vsctl show
```

* Now you can use P4Runtime-shell to configure P4 table entries:

```bash
./p4runtime-sh-docker --grpc-addr 172.17.0.1:50051 --device-id 0
```

* 

* Run ``ping`` between namespaces, traffic should be forwarded via P4 bridge:

```bash
$ ip netns exec ns0 ping -i .2 10.1.1.2
```
