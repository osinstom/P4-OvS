![GitHub release](https://img.shields.io/github/v/tag/osinstom/P4-OvS.svg?sort=semver)

P4-OvS - Bringing the power of P4 to OvS!
=========================================

The original Open vSwitch README is available at [README-original.rst](./README-original.rst).

# Introduction

This repository implements the [P4](https://p4.org)-capable Open vSwitch with the [P4Runtime](https://p4.org/api/p4-runtime-putting-the-control-plane-in-charge-of-the-forwarding-plane.html) interface. 

In order to fill the gap in the P4 ecosystem (lack of efficient P4 software switch) the ambition of this project is to 
build a high-performance P4 software switch based on Open vSwitch. I believe that P4 needs the same, what Open vSwitch was for OpenFlow.

The P4-OvS is built on top of the following technologies:

- **Open vSwitch** as a packet processing framework
- **uBPF (userspace BPF)** as the re-configurable packet processing engine
- **p4c-ubpf** as the compiler enabling translation of P4 programs to BPF-compatible C code

Please, check [changelog](Documentation/topics/p4/changelog.md) for details on what has been implemented so far.

**Note!** The current version of P4-OVS is still a research project and it almost certainly contains serious bugs or code quirks.

# Getting started

To play with P4-OVS on your own follow [Getting started](./Documentation/topics/p4/getting-started.md) guide.

The current version of the project allows to:

* create a single P4 bridge and provide a P4 program as configuration parameter or using P4Runtime and SetForwardingPipelineConfig RPC.
* add ports to the bridge
* receive traffic from these ports and handle it in the P4 (uBPF) datapath.
* control P4 tables via `ovs-p4ctl` tool

Please, refer to [the usage guide](./Documentation/topics/p4/usage.md) to learn how to use `ovs-p4ctl` tool.

# Contributing

The idea behind this project is to get feedback from the community and gather volunteers (developers, users, architects, etc.) willing to help with further development of this project. 

All kinds of contributions are more than welcome! You can start from:

* Check out the [Design proposal](Documentation/topics/p4/design.md). This project follows a documentation-driven approach. Your feedback is more than welcome! Feel free to throw your ideas in!
* [Join the discussion](Documentation/topics/p4/getting-started.md#join-the-discussion) to discuss the current design, propose a new feature or discuss the future of the project.
* If you see some inconsistency in the documentation or you want to propose/implement a new feature please [Open an issue](https://github.com/osinstom/P4-OvS/issues/new).

You can also reach me out on [Twitter](https://twitter.com/tomek_osinski) or via [email](mailto:osinstom@gmail.com) to discuss the project!

**Note!** I am currently looking for someone, who is willing to start developing the XDP datapath in parallel. Please, reach me out if you want to contribute the XDP datapath!

# Project status

P4-OvS already implements the most important features of the P4 switch. You can run & test it! However, some P4 features 
(e.g. counters, registers) are not implemented yet.

# Roadmap

The project's goal is to develop this PoC into a high-performance P4 software switch.
There is a long list of exciting features to be implemented on the [Roadmap](./Documentation/topics/p4/roadmap.md) page.