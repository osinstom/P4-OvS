# Release notes

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

## 0.2.0 - 2020-06-06

### Added

- Initial implementation of gRPC server 

### Changed

- Enable per bridge P4 program (previously only one P4 bridge might be created)

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

