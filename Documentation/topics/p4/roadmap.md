Roadmap
=======

This document lists the target feature set (TODO list) of a high-performance P4 software switch with P4Runtime interface.
The current list is a result of the current design proposal, which can change over time and so this list is likely to evolve.

Setting up a project
--------------------

There must be some initial decisions made before the actual code development will begin. Tasks to be done:

* Should the project target to become a part of the Open vSwitch project in the future? It probably depends on whether the OVS community will be welcome to accept such a significant change in the way how the OVS works.

* Create the name of the project :) The "P4-OvS" name is just a draft name.

Upcoming features
--------

* **XDP datapath** - the modular design of P4-OvS enables integration of different datapaths. XDP should be integrated with OvS.p4 too.

* **Support for Portable Switch Architecture** - p4c-ubpf does not support PSA yet. The target P4 architecture for this project should be PSA, but it needs to be implemented in p4c-ubpf.

* **Enhancements to P4 compiler** - p4c-ubpf still does not support some P4 features (e.g. some P4 externs). P4-OvS should contribute further enhancements to `p4c-ubpf` and/or `p4c-xdp`.

* **Enhancements to the implementation of the P4Runtime interface** - currently, only a subset of the P4 specification is implemented by P4-OvS. We will gradually improve P4-OvS to be in line with the P4 specs.

* **Performance optimizations**

