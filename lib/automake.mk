# Copyright (C) 2009-2018 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

lib_LTLIBRARIES += lib/libopenvswitch.la

lib_libopenvswitch_la_LIBADD = $(SSL_LIBS)
lib_libopenvswitch_la_LIBADD += $(CAPNG_LDADD)
lib_libopenvswitch_la_LIBADD += $(LIBBPF_LDADD)
lib_libopenvswitch_la_LIBADD += -lpip4info


if WIN32
lib_libopenvswitch_la_LIBADD += ${PTHREAD_LIBS}
endif

lib_libopenvswitch_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/lib/libopenvswitch.sym \
        $(AM_LDFLAGS)

if HAVE_AVX512F
if HAVE_LD_AVX512_GOOD
# Build library of avx512 code with CPU ISA CFLAGS enabled. This allows the
# compiler to use the ISA features required for the ISA optimized code-paths.
# Use LDFLAGS to compile only static library of this code, as it should be
# statically linked into vswitchd even if vswitchd is a shared build.
lib_LTLIBRARIES += lib/libopenvswitchavx512.la
lib_libopenvswitch_la_LIBADD += lib/libopenvswitchavx512.la
lib_libopenvswitchavx512_la_CFLAGS = \
	-mavx512f \
	-mavx512bw \
	-mavx512dq \
	-mbmi2 \
	-fPIC \
	$(AM_CFLAGS)
lib_libopenvswitchavx512_la_SOURCES = \
	lib/dpif-netdev-lookup-avx512-gather.c
lib_libopenvswitchavx512_la_LDFLAGS = \
	-static
endif
endif

# Build core vswitch libraries as before
lib_libopenvswitch_la_SOURCES = \
	lib/aes128.c \
	lib/aes128.h \
	lib/async-append.h \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bfd.c \
	lib/bfd.h \
	lib/bitmap.h \
	lib/bpf/ubpf.h \
	lib/bpf/ebpf.h \
	lib/bpf/ubpf_int.h \
	lib/bpf/ubpf_vm.c \
	lib/bpf/lookup3.c \
	lib/bpf/lookup3.h \
	lib/bpf/ubpf_jit_x86_64.c \
	lib/bpf/ubpf_jit_x86_64.h \
	lib/bpf/ubpf_array.c \
	lib/bpf/ubpf_array.h \
	lib/bpf/ubpf_bf.c \
	lib/bpf/ubpf_bf.h \
	lib/bpf/ubpf_countmin.c \
	lib/bpf/ubpf_countmin.h \
	lib/bpf/ubpf_hashmap.c \
	lib/bpf/ubpf_hashmap.h \
	lib/bpf/ubpf_loader.c \
	lib/bpf/ubpf_lpm_trie.c \
	lib/bpf/ubpf_lpm_trie.h \
	lib/bpf.c \
	lib/bpf.h \
	lib/bundle.c \
	lib/bundle.h \
	lib/byte-order.h \
	lib/byteq.c \
	lib/byteq.h \
	lib/cfm.c \
	lib/cfm.h \
	lib/classifier.c \
	lib/classifier.h \
	lib/classifier-private.h \
	lib/ccmap.c \
	lib/ccmap.h \
	lib/cmap.c \
	lib/cmap.h \
	lib/colors.c \
	lib/colors.h \
	lib/command-line.c \
	lib/command-line.h \
	lib/compiler.h \
	lib/connectivity.c \
	lib/connectivity.h \
	lib/conntrack-icmp.c \
	lib/conntrack-private.h \
	lib/conntrack-tcp.c \
	lib/conntrack-tp.c \
	lib/conntrack-tp.h \
	lib/conntrack-other.c \
	lib/conntrack.c \
	lib/conntrack.h \
	lib/coverage.c \
	lib/coverage.h \
	lib/crc32c.c \
	lib/crc32c.h \
	lib/csum.c \
	lib/csum.h \
	lib/ct-dpif.c \
	lib/ct-dpif.h \
	lib/daemon.c \
	lib/daemon.h \
	lib/daemon-private.h \
	lib/db-ctl-base.c \
	lib/db-ctl-base.h \
	lib/dhcp.h \
	lib/dummy.c \
	lib/dummy.h \
	lib/dhparams.h \
	lib/dirs.h \
	lib/dpctl.c \
	lib/dpctl.h \
	lib/dp-packet.h \
	lib/dp-packet.c \
	lib/dpdk.h \
	lib/dpif-netdev-lookup.h \
	lib/dpif-netdev-lookup.c \
	lib/dpif-netdev-lookup-autovalidator.c \
	lib/dpif-netdev-lookup-generic.c \
	lib/dpif-netdev.c \
	lib/dpif-netdev.h \
	lib/dpif-netdev-private.h \
	lib/dpif-netdev-perf.c \
	lib/dpif-netdev-perf.h \
	lib/dpif-provider.h \
	lib/dpif-ubpf.c \
	lib/dpif.c \
	lib/dpif.h \
	lib/heap.c \
	lib/heap.h \
	lib/dynamic-string.c \
	lib/entropy.c \
	lib/entropy.h \
	lib/fat-rwlock.c \
	lib/fat-rwlock.h \
	lib/fatal-signal.c \
	lib/fatal-signal.h \
	lib/flow.c \
	lib/flow.h \
	lib/guarded-list.c \
	lib/guarded-list.h \
	lib/hash.c \
	lib/hash.h \
	lib/hash-aarch64.h \
	lib/hindex.c \
	lib/hindex.h \
	lib/hmap.c \
	lib/hmapx.c \
	lib/hmapx.h \
	lib/id-pool.c \
	lib/id-pool.h \
	lib/if-notifier-manual.c \
	lib/if-notifier.h \
	lib/ipf.c \
	lib/ipf.h \
	lib/jhash.c \
	lib/jhash.h \
	lib/json.c \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/lacp.c \
	lib/lacp.h \
	lib/latch.h \
	lib/learn.c \
	lib/learn.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/lockfile.c \
	lib/lockfile.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/match.c \
	lib/mcast-snooping.c \
	lib/mcast-snooping.h \
	lib/memory.c \
	lib/memory.h \
	lib/meta-flow.c \
	lib/multipath.c \
	lib/multipath.h \
	lib/namemap.c \
	lib/netdev-dpdk.h \
	lib/netdev-dummy.c \
	lib/netdev-offload.c \
	lib/netdev-offload.h \
	lib/netdev-offload-provider.h \
	lib/netdev-provider.h \
	lib/netdev-vport.c \
	lib/netdev-vport.h \
	lib/netdev-vport-private.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/netflow.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/netnsid.h \
	lib/nx-match.c \
	lib/nx-match.h \
	lib/object-collection.c \
	lib/object-collection.h \
	lib/odp-execute.c \
	lib/odp-execute.h \
	lib/odp-util.c \
	lib/odp-util.h \
	lib/ofp-actions.c \
	lib/ofp-bundle.c \
	lib/ofp-connection.c \
	lib/ofp-ed-props.c \
	lib/ofp-errors.c \
	lib/ofp-flow.c \
	lib/ofp-group.c \
	lib/ofp-ipfix.c \
	lib/ofp-match.c \
	lib/ofp-meter.c \
	lib/ofp-monitor.c \
	lib/ofp-msgs.c \
	lib/ofp-packet.c \
	lib/ofp-parse.c \
	lib/ofp-port.c \
	lib/ofp-print.c \
	lib/ofp-prop.c \
	lib/ofp-protocol.c \
	lib/ofp-queue.c \
	lib/ofp-switch.c \
	lib/ofp-table.c \
	lib/ofp-util.c \
	lib/ofp-version-opt.h \
	lib/ofp-version-opt.c \
	lib/ofpbuf.c \
	lib/ovs-atomic-c++.h \
	lib/ovs-atomic-c11.h \
	lib/ovs-atomic-clang.h \
	lib/ovs-atomic-flag-gcc4.7+.h \
	lib/ovs-atomic-gcc4+.h \
	lib/ovs-atomic-gcc4.7+.h \
	lib/ovs-atomic-i586.h \
	lib/ovs-atomic-locked.c \
	lib/ovs-atomic-locked.h \
	lib/ovs-atomic-msvc.h \
	lib/ovs-atomic-pthreads.h \
	lib/ovs-atomic-x86_64.h \
	lib/ovs-atomic.h \
	lib/ovs-lldp.c \
	lib/ovs-lldp.h \
	lib/ovs-numa.c \
	lib/ovs-numa.h \
	lib/ovs-rcu.c \
	lib/ovs-rcu.h \
	lib/ovs-router.h \
	lib/ovs-router.c \
	lib/ovs-thread.c \
	lib/ovs-thread.h \
	lib/ovsdb-data.c \
	lib/ovsdb-data.h \
	lib/ovsdb-error.c \
	lib/ovsdb-error.h \
	lib/ovsdb-idl-provider.h \
	lib/ovsdb-idl.c \
	lib/ovsdb-idl.h \
	lib/ovsdb-map-op.c \
	lib/ovsdb-map-op.h \
	lib/ovsdb-set-op.c \
	lib/ovsdb-set-op.h \
	lib/ovsdb-condition.h \
	lib/ovsdb-condition.c \
	lib/ovsdb-parser.c \
	lib/ovsdb-parser.h \
	lib/ovsdb-session.c \
	lib/ovsdb-session.h \
	lib/ovsdb-types.c \
	lib/ovsdb-types.h \
	lib/ox-stat.c \
	lib/ox-stat.h \
	lib/p4rt-objects.h \
	lib/packets.c \
	lib/packets.h \
	lib/pcap-file.c \
	lib/pcap-file.h \
	lib/perf-counter.h \
	lib/perf-counter.c \
	lib/stopwatch.h \
	lib/stopwatch.c \
	lib/poll-loop.c \
	lib/process.c \
	lib/process.h \
	lib/pvector.c \
	lib/pvector.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
	lib/rculist.h \
	lib/reconnect.c \
	lib/reconnect.h \
	lib/rstp.c \
	lib/rstp.h \
	lib/rstp-common.h \
	lib/rstp-state-machines.c \
	lib/rstp-state-machines.h \
	lib/sat-math.h \
	lib/seq.c \
	lib/seq.h \
	lib/sha1.c \
	lib/sha1.h \
	lib/shash.c \
	lib/simap.c \
	lib/simap.h \
	lib/skiplist.c \
	lib/skiplist.h \
	lib/smap.c \
	lib/smap.h \
	lib/socket-util.c \
	lib/socket-util.h \
	lib/sort.c \
	lib/sort.h \
	lib/sset.c \
	lib/sset.h \
	lib/stp.c \
	lib/stp.h \
	lib/stream-fd.c \
	lib/stream-fd.h \
	lib/stream-provider.h \
	lib/stream-ssl.h \
	lib/stream-tcp.c \
	lib/stream.c \
	lib/stream.h \
	lib/stdio.c \
	lib/string.c \
	lib/svec.c \
	lib/svec.h \
	lib/syslog-direct.c \
	lib/syslog-direct.h \
	lib/syslog-libc.c \
	lib/syslog-libc.h \
	lib/syslog-null.c \
	lib/syslog-null.h \
	lib/syslog-provider.h \
	lib/table.c \
	lib/table.h \
	lib/timer.c \
	lib/timer.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/tnl-neigh-cache.c \
	lib/tnl-neigh-cache.h \
	lib/tnl-ports.c \
	lib/tnl-ports.h \
	lib/netdev-native-tnl.c \
	lib/netdev-native-tnl.h \
	lib/token-bucket.c \
	lib/tun-metadata.c \
	lib/tun-metadata.h \
	lib/unaligned.h \
	lib/unicode.c \
	lib/unicode.h \
	lib/unixctl.c \
	lib/unixctl.h \
	lib/userspace-tso.c \
	lib/userspace-tso.h \
	lib/util.c \
	lib/util.h \
	lib/uuid.c \
	lib/uuid.h \
	lib/valgrind.h \
	lib/vconn-provider.h \
	lib/vconn-stream.c \
	lib/vconn.c \
	lib/versions.h \
	lib/vl-mff-map.h \
	lib/vlan-bitmap.c \
	lib/vlan-bitmap.h \
	lib/vlog.c \
	lib/lldp/aa-structs.h \
	lib/lldp/lldp.c \
	lib/lldp/lldp-const.h \
	lib/lldp/lldp-tlv.h \
	lib/lldp/lldpd.c \
	lib/lldp/lldpd.h \
	lib/lldp/lldpd-structs.c \
	lib/lldp/lldpd-structs.h

if WIN32
lib_libopenvswitch_la_SOURCES += \
	lib/daemon-windows.c \
	lib/getopt_long.c \
	lib/getrusage-windows.c \
	lib/latch-windows.c \
	lib/route-table-stub.c \
	lib/if-notifier-stub.c \
	lib/stream-windows.c \
	lib/strsep.c
else
lib_libopenvswitch_la_SOURCES += \
	lib/daemon-unix.c \
	lib/latch-unix.c \
	lib/signals.c \
	lib/signals.h \
	lib/socket-util-unix.c \
	lib/stream-unix.c
endif

EXTRA_DIST += \
	lib/stdio.h.in \
	lib/string.h.in

nodist_lib_libopenvswitch_la_SOURCES = \
	lib/dirs.c \
	lib/ovsdb-server-idl.c \
	lib/ovsdb-server-idl.h \
	lib/vswitch-idl.c \
	lib/vswitch-idl.h
CLEANFILES += $(nodist_lib_libopenvswitch_la_SOURCES)

lib_LTLIBRARIES += lib/libsflow.la
lib_libsflow_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/lib/libsflow.sym \
        $(AM_LDFLAGS)
lib_libsflow_la_SOURCES = \
	lib/sflow_api.h \
	lib/sflow.h \
	lib/sflow_agent.c \
	lib/sflow_sampler.c \
	lib/sflow_poller.c \
	lib/sflow_receiver.c
lib_libsflow_la_CPPFLAGS = $(AM_CPPFLAGS)
lib_libsflow_la_CFLAGS = $(AM_CFLAGS)
if HAVE_WNO_UNUSED
lib_libsflow_la_CFLAGS += -Wno-unused
endif
if HAVE_WNO_UNUSED_PARAMETER
lib_libsflow_la_CFLAGS += -Wno-unused-parameter
endif

if LINUX
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-netlink.c \
	lib/dpif-netlink.h \
	lib/dpif-netlink-rtnl.c \
	lib/dpif-netlink-rtnl.h \
	lib/if-notifier.c \
	lib/netdev-linux.c \
	lib/netdev-linux.h \
	lib/netdev-linux-private.h \
	lib/netdev-offload-tc.c \
	lib/netlink-conntrack.c \
	lib/netlink-conntrack.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/rtnetlink.c \
	lib/rtnetlink.h \
	lib/route-table.c \
	lib/route-table.h \
	lib/tc.c \
	lib/tc.h
endif

if HAVE_AF_XDP
lib_libopenvswitch_la_SOURCES += \
	lib/netdev-afxdp-pool.c \
	lib/netdev-afxdp-pool.h \
	lib/netdev-afxdp.c \
	lib/netdev-afxdp.h
endif

if DPDK_NETDEV
lib_libopenvswitch_la_SOURCES += \
	lib/dpdk.c \
	lib/netdev-dpdk.c \
	lib/netdev-offload-dpdk.c
else
lib_libopenvswitch_la_SOURCES += \
	lib/dpdk-stub.c
endif

if WIN32
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-netlink.c \
	lib/dpif-netlink.h \
	lib/dpif-netlink-rtnl.h \
	lib/netdev-windows.c \
	lib/netlink-conntrack.c \
	lib/netlink-conntrack.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/wmi.c \
	lib/wmi.h
endif

if HAVE_POSIX_AIO
lib_libopenvswitch_la_SOURCES += lib/async-append-aio.c
else
lib_libopenvswitch_la_SOURCES += lib/async-append-null.c
endif

if HAVE_IF_DL
lib_libopenvswitch_la_SOURCES += \
	lib/if-notifier-bsd.c \
	lib/netdev-bsd.c \
	lib/rtbsd.c \
	lib/rtbsd.h \
	lib/route-table-bsd.c
endif

.PHONY: generate-dhparams-c
if HAVE_OPENSSL
lib_libopenvswitch_la_SOURCES += lib/stream-ssl.c lib/dhparams.c

# Manually regenerates lib/dhparams.c.  Not normally necessary since
# lib/dhparams.c is part of the repository and doesn't normally need
# updates.
generate-dhparams-c:
	$(AM_V_GEN)cd $(srcdir) && \
	build-aux/generate-dhparams-c > lib/dhparams.c.tmp && \
	mv lib/dhparams.c.tmp lib/dhparams.c
else
lib_libopenvswitch_la_SOURCES += lib/stream-nossl.c
endif

lib_libopenvswitch_la_SOURCES += lib/dns-resolve.h
if HAVE_UNBOUND
lib_libopenvswitch_la_SOURCES += lib/dns-resolve.c
else
lib_libopenvswitch_la_SOURCES += lib/dns-resolve-stub.c
endif

pkgconfig_DATA += \
	lib/libopenvswitch.pc \
	lib/libsflow.pc

EXTRA_DIST += \
	lib/dh1024.pem \
	lib/dh2048.pem \
	lib/dh4096.pem \
	lib/common.xml \
	lib/daemon.xml \
	lib/dirs.c.in \
	lib/db-ctl-base.xml \
	lib/ssl.xml \
	lib/ssl-bootstrap.xml \
	lib/ssl-peer-ca-cert.xml \
	lib/table.xml \
	lib/vlog.xml \
	lib/unixctl.xml

MAN_FRAGMENTS += \
	lib/colors.man \
	lib/common.man \
	lib/common-syn.man \
	lib/coverage-unixctl.man \
	lib/daemon.man \
	lib/daemon-syn.man \
	lib/db-ctl-base.man \
	lib/dpctl.man \
	lib/dpdk-unixctl.man \
	lib/memory-unixctl.man \
	lib/netdev-dpdk-unixctl.man \
	lib/dpif-netdev-unixctl.man \
	lib/ofp-version.man \
	lib/ovs.tmac \
	lib/service.man \
	lib/service-syn.man \
	lib/ssl-bootstrap.man \
	lib/ssl-bootstrap-syn.man \
	lib/ssl-peer-ca-cert.man \
	lib/ssl-peer-ca-cert-syn.man \
	lib/ssl.man \
	lib/ssl-syn.man \
	lib/ssl-connect.man \
	lib/ssl-connect-syn.man \
	lib/table.man \
	lib/unixctl.man \
	lib/unixctl-syn.man \
	lib/vconn-active.man \
	lib/vconn-passive.man \
	lib/vlog-unixctl.man \
	lib/vlog-syn.man \
	lib/vlog.man

# vswitch IDL
OVSIDL_BUILT += lib/vswitch-idl.c lib/vswitch-idl.h lib/vswitch-idl.ovsidl

EXTRA_DIST += lib/vswitch-idl.ann
lib/vswitch-idl.ovsidl: vswitchd/vswitch.ovsschema lib/vswitch-idl.ann
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(srcdir)/vswitchd/vswitch.ovsschema $(srcdir)/lib/vswitch-idl.ann > $@.tmp && mv $@.tmp $@

lib/dirs.c: lib/dirs.c.in Makefile
	$(AM_V_GEN)($(ro_c) && sed < $(srcdir)/lib/dirs.c.in \
		-e 's,[@]srcdir[@],$(srcdir),g' \
		-e 's,[@]LOGDIR[@],"$(LOGDIR)",g' \
		-e 's,[@]RUNDIR[@],"$(RUNDIR)",g' \
		-e 's,[@]DBDIR[@],"$(DBDIR)",g' \
		-e 's,[@]bindir[@],"$(bindir)",g' \
		-e 's,[@]sysconfdir[@],"$(sysconfdir)",g' \
		-e 's,[@]pkgdatadir[@],"$(pkgdatadir)",g') \
	     > lib/dirs.c.tmp && \
	mv lib/dirs.c.tmp lib/dirs.c

lib/meta-flow.inc: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h
	$(AM_V_GEN)$(run_python) $< meta-flow $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
lib/meta-flow.lo: lib/meta-flow.inc
lib/nx-match.inc: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h 
	$(AM_V_GEN)$(run_python) $< nx-match $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
lib/nx-match.lo: lib/nx-match.inc
CLEANFILES += lib/meta-flow.inc lib/nx-match.inc
EXTRA_DIST += build-aux/extract-ofp-fields

lib/ofp-actions.inc1: $(srcdir)/build-aux/extract-ofp-actions lib/ofp-actions.c
	$(AM_V_GEN)$(run_python) $< prototypes $(srcdir)/lib/ofp-actions.c > $@.tmp && mv $@.tmp $@
lib/ofp-actions.inc2: $(srcdir)/build-aux/extract-ofp-actions lib/ofp-actions.c
	$(AM_V_GEN)$(run_python) $< definitions $(srcdir)/lib/ofp-actions.c > $@.tmp && mv $@.tmp $@
lib/ofp-actions.lo: lib/ofp-actions.inc1 lib/ofp-actions.inc2
CLEANFILES += lib/ofp-actions.inc1 lib/ofp-actions.inc2
EXTRA_DIST += build-aux/extract-ofp-actions

lib/ofp-errors.inc: include/openvswitch/ofp-errors.h include/openflow/openflow-common.h \
	$(srcdir)/build-aux/extract-ofp-errors
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-errors \
		$(srcdir)/include/openvswitch/ofp-errors.h \
		$(srcdir)/include/openflow/openflow-common.h > $@.tmp && \
	mv $@.tmp $@
lib/ofp-errors.lo: lib/ofp-errors.inc
CLEANFILES += lib/ofp-errors.inc
EXTRA_DIST += build-aux/extract-ofp-errors

lib/ofp-msgs.inc: include/openvswitch/ofp-msgs.h $(srcdir)/build-aux/extract-ofp-msgs
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-msgs \
		$(srcdir)/include/openvswitch/ofp-msgs.h $@ > $@.tmp && mv $@.tmp $@
lib/ofp-msgs.lo: lib/ofp-msgs.inc
CLEANFILES += lib/ofp-msgs.inc
EXTRA_DIST += build-aux/extract-ofp-msgs

# _server IDL
OVSIDL_BUILT += lib/ovsdb-server-idl.c lib/ovsdb-server-idl.h lib/ovsdb-server-idl.ovsidl
EXTRA_DIST += lib/ovsdb-server-idl.ann
lib/ovsdb-server-idl.ovsidl: ovsdb/_server.ovsschema lib/ovsdb-server-idl.ann
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(srcdir)/ovsdb/_server.ovsschema $(srcdir)/lib/ovsdb-server-idl.ann > $@.tmp && mv $@.tmp $@

INSTALL_DATA_LOCAL += lib-install-data-local
lib-install-data-local:
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/openvswitch

man_MANS += lib/ovs-fields.7
CLEANFILES += lib/ovs-fields.7
lib/ovs-fields.7: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h lib/meta-flow.xml
	$(AM_V_GEN)PYTHONIOENCODING=utf8 $(run_python) $< \
            --ovs-version=$(VERSION) ovs-fields \
	    $(srcdir)/include/openvswitch/meta-flow.h \
            $(srcdir)/lib/meta-flow.xml > $@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += lib/meta-flow.xml

man_MANS += lib/ovs-actions.7
CLEANFILES += lib/ovs-actions.7
lib/ovs-actions.7: $(srcdir)/build-aux/extract-ofp-actions lib/ovs-actions.xml
	$(AM_V_GEN)PYTHONIOENCODING=utf8 $(run_python) $< \
            --ovs-version=$(VERSION) ovs-actions \
            $(srcdir)/lib/ovs-actions.xml > $@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += lib/ovs-actions.xml
