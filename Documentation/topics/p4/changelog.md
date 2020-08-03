# Release notes

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

## 0.4.0

### Added

- Implementation of ovs-p4ctl utility tool (supported commands: show, set-pipe, get-pipe, add-entry, del-entry, dump-entries)
- Support for Read RPC to fetch P4 Table Entries
- Support for Write RPC to delete P4 Table Entry

## 0.3.0 - 2020-07-01

### Added

- Enable running multiple P4 bridges simultaneously; each P4 bridge has its own P4 program
- PTF tests for uBPF datapath
- Enable user-defined "Device ID" of P4Runtime bridge
- Automatically generate and assign "Device ID" if not provided by a user
- Support for Write RPC for P4 Table Entry

## 0.2.0 - 2020-06-06

### Added

- Initial implementation of gRPC server 
- Support for SetForwardingPipelineConfig RPC
- Support for GetForwardingPipelineConfig RPC
- Added functional tests for P4 bridges

### Fixed

- Don't create a P4Runtime bridge if pre-configured P4 program is not initialized successfully.

## 0.1.1 - 2020-05-23

### Added

- Show type of a bridge in the output of `ovs-vsctl show`.
- Enable packet drop (uBPF datapath)

### Changed

- Enable user-defined port numbers (previous implementation relies on port allocation done by uBPF datapath)

### Fixed

- Disable `ovs-ofctl` for a P4 bridge
- Fix memory leaks in the uBPF datapath

## 0.1.0 - 2020-05-15

### Added

- uBPF virtual machine integrated with OVS. uBPF VM is based on the [Oko](https://github.com/Orange-OpenSource/Oko) switch.
- Intiial support for uBPF datapath based on `dpif-netdev`. 
- P4Runtime switch abstractions to manage datapath's ports and P4 program. 
- Modifications to OVS bridge implementation and OVSDB to support OVS bridge of type "P4". 

