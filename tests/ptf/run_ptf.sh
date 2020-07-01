#! /bin/bash

setup_intfs() {
  ip netns add ns0
  ip link add p0 type veth peer name ovsp4-p0
  ip link set p0 netns ns0
  ip link set dev ovsp4-p0 up
  ip netns exec ns0 sh -c "ip addr add "10.1.1.1/24" dev p0"
  ip netns exec ns0 sh -c "ip link set dev p0 up"

  ip netns add ns1
  ip link add p1 type veth peer name ovsp4-p1
  ip link set p1 netns ns1
  ip link set dev ovsp4-p1 up

  ip netns exec ns1 sh -c "ip addr add "10.1.1.2/24" dev p1"
  ip netns exec ns1 sh -c "ip link set dev p1 up"
}

ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --verbose --detach

ovs-vswitchd --pidfile --detach --log-file=ovs-ptf.log

python compile.py

#setup_intfs

ptf --failfast --test-dir tests/ --interface 0@veth0 --interface 1@veth2 --verbose

ovs-appctl -t ovs-vswitchd exit
ovs-appctl -t ovsdb-server exit