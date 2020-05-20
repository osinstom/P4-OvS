ip netns add ns0

ip link add p0 type veth peer name ovsp4-p0

ip link set p0 netns ns0

ip link set dev ovsp4-p0 up

ip netns exec ns0 sh << NS_EXEC_HEREDOC
ip addr add "10.1.1.1/24" dev p0
ip link set dev p0 up
NS_EXEC_HEREDOC

ip netns add ns1

ip link add p1 type veth peer name ovsp4-p1

ip link set p1 netns ns1

ip link set dev ovsp4-p1 up

ip netns exec ns1 sh << NS_EXEC_HEREDOC
ip addr add "10.1.1.2/24" dev p1
ip link set dev p1 up
NS_EXEC_HEREDOC

