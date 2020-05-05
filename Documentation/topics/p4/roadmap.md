Roadmap
=======

This document lists the target feature set (TODO list) of a high-performance P4 software switch with P4Runtime interface.
The current list is a result of the current design proposal, which can change over time and so this list is likely to evolve.

Setting up a project
--------------------

There must be some initial decisions made before the actual code development will begin. Tasks to be done:

* Should the project target to become a part of the Open vSwitch project in the future? It probably depends on whether the OVS community will be welcome to accept such a significant change in the way how the OVS works.

* Create the name of the project :) The "OvS.p4" name is just a draft name.

Features
--------

The following features are considered for the first release of the project:

* **P4Runtime switch abstractions for OVS** - Build software abstractions to manage reconfigurable P4 datapath and integrate P4Runtime switch as a new type of OVS bridge.

* **P4Runtime interface** - Create gRPC server as part of P4Runtime switch and expose P4Runtime control interface.

* **uBPF datapath** - Make use of [p4c-ubpf](https://github.com/p4lang/p4c/tree/master/backends/ubpf) to generate userspace packet processing pipeline from the P4 program and create a new OVS datapath able to consume this pipeline.

* **ovs-p4ctl utility** - the P4 bridge should be have its own management CLI tool. The first version should support installing and deleting P4 program plus adding/updating/removing/reading table entries.

* **Port forwarding** - develop mechanisms in uBPF datapath that allow to determine and enforce output port from within the P4 program.

The following features should be added in the further releases of the project:

* **XDP datapath** - the modular design of OvS.p4 enables integration of different datapaths. XDP should be integrated with OvS.p4 too.

* **Support for Portable Switch Architecture** - p4c-ubpf does not support PSA yet. The target P4 architecture for this project should be PSA, but it needs to be implemented in p4c-ubpf.

* **Performance optimizations**






