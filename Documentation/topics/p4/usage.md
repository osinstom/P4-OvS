This page describes how to use `ovs-p4ctl` management utility to control P4-OvS. 

**Note!** As `ovs-p4ctl` makes use of OVSDB it requires to setup OVSDB manager listening on port TCP/5000:

```bash
$ ovs-vsctl set-manager ptcp:5000
```

The current version of P4-OVS support the following `ovs-p4ctl`'s commands:

```bash
$ ovs-p4ctl --help
  usage: ovs-p4ctl: P4Runtime switch management utility
  usage: ovs-p4ctl [OPTIONS] COMMAND [ARG...]
  
  For P4Runtime switches:
    show SWITCH                     show P4Runtime switch information
    set-pipe SWITCH PROGRAM P4INFO  set P4 pipeline for the swtich
    get-pipe SWITCH                 print raw P4Info representation of P4 program
    add-entry SWITCH TABLE FLOW     add new table entry
    del-entry SWITCH TABLE KEY      delete a table entry with KEY from TABLE
    dump-entries SWITCH [TBL]       print table entries
  
  positional arguments:
    command     Subcommand to run
  
  optional arguments:
    -h, --help  show this help message and exit
```

To show information about a P4Runtime bridge use `ovs-p4ctl show`, for example:

```bash
$ ovs-p4ctl show br-test
P4Runtime switch br-test information:
device_id: 3
n_tables: 1
tables: pipe.test_tbl(match=[hdr.ethernet.srcAddr], actions=[pipe.forward, NoAction])
  3(ovsp4-p0):
        state: da:2d:10:6d:8b:d1
        addr:UP
        speed: 10000000 Mbps
        stats: rx_packets=13690, rx_bytes=257, tx_packets=215, tx_bytes=15339
  2(ovsp4-p1):
        state: 92:72:2c:4b:1a:ba
        addr:UP
        speed: 10000000 Mbps
        stats: rx_packets=5878, rx_bytes=71, tx_packets=117, tx_bytes=11251
  LOCAL(br-test):
        state: 92:e7:f6:0b:8c:f4
        addr:DOWN
        speed: 10000 Mbps
        stats: rx_packets=0, rx_bytes=0, tx_packets=0, tx_bytes=0
```

The above command will not work if ForwardingPipelineConfig is not set for the bridge. In such case, the following
error will be returned:

```bash
$ ovs-p4ctl show br0
Error: P4Runtime RPC error (FAILED_PRECONDITION): No forwarding pipeline config set for this device
```

To set the ForwardingPipelineConfig for the bridge run the following command (assuming `demo.o` is BPF-compatible bytecode
and `demo.json` is P4Info file):

```bash
$ ovs-p4ctl set-pipe br0 test.o test.json
```

You can also retrieve a raw P4Info description of the ForwardingPipelineConfig:

```bash
$ ovs-p4ctl get-pipe br-test
P4Info of bridge br-test:
tables {
  preamble {
    id: 49903939
    name: "pipe.test_tbl"
    alias: "test_tbl"
  }
  match_fields {
    id: 1
    name: "hdr.ethernet.srcAddr"
    bitwidth: 48
    match_type: EXACT
  }
  action_refs {
    id: 20655602
  }
  action_refs {
    id: 21257015
    scope: DEFAULT_ONLY
  }
  size: 1024
}
actions {
  preamble {
    id: 20655602
    name: "pipe.forward"
    alias: "forward"
  }
  params {
    id: 1
    name: "output"
    bitwidth: 32
  }
}
actions {
  preamble {
    id: 21257015
    name: "NoAction"
    annotations: "@noWarn(\"unused\")"
  }
}
```

To add a new table entry, use the following command:

```bash
$ ovs-p4ctl add-entry br-test pipe.test_tbl hdr.ethernet.srcAddr=12:e1:0e:f6:3f:ff,action="pipe.forward(5)"
```

In general, the match key's and action data's parameters must be provided as integers, but `ovs-p4ctl` will also recognize
MAC format (e.g. 12:e1:0e:f6:3f:ff) or IPv4 format (e.g. 10.10.10.10). Providing parameters in the hexadecimal format is not supported yet.

To fetch table entries you should use `ovs-p4ctl dump-entries`:

```bash
# Note: if you will not provide TBL name all tables will be queried.
$ ovs-p4ctl dump-entries br-test [pipe.test_tbl]
Table entries for bridge br-test:
  table=pipe.test_tbl priority=0 hdr.ethernet.srcAddr=0x12e10ef63f8e actions=pipe.forward(output=0x00000004)
```

Note that `dump-entries` command will always return match keys and action data in the hexadecimal format.

To delete a table entry use the following command:

```bash
$ ovs-p4ctl del-entry br-test pipe.test_tbl hdr.ethernet.srcAddr=12:e1:0e:f6:3f:ff
```


