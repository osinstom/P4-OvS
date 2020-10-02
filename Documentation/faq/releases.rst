..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

========
Releases
========

Q: What does it mean for an Open vSwitch release to be LTS (long-term support)?

    A: All official releases have been through a comprehensive testing process
    and are suitable for production use.  Planned releases occur twice a year.
    If a significant bug is identified in an LTS release, we will provide an
    updated release that includes the fix.  Releases that are not LTS may not
    be fixed and may just be supplanted by the next major release.  The current
    LTS release is 2.5.x.

    For more information on the Open vSwitch release process, refer to
    :doc:`/internals/release-process`.

Q: What Linux kernel versions does each Open vSwitch release work with?

    A: The following table lists the Linux kernel versions against which the
    given versions of the Open vSwitch kernel module will successfully build.
    The Linux kernel versions are upstream kernel versions, so Linux kernels
    modified from the upstream sources may not build in some cases even if they
    are based on a supported version.  This is most notably true of Red Hat
    Enterprise Linux (RHEL) kernels, which are extensively modified from
    upstream.

    ============ ==============
    Open vSwitch Linux kernel
    ============ ==============
    1.4.x        2.6.18 to 3.2
    1.5.x        2.6.18 to 3.2
    1.6.x        2.6.18 to 3.2
    1.7.x        2.6.18 to 3.3
    1.8.x        2.6.18 to 3.4
    1.9.x        2.6.18 to 3.8
    1.10.x       2.6.18 to 3.8
    1.11.x       2.6.18 to 3.8
    2.0.x        2.6.32 to 3.10
    2.1.x        2.6.32 to 3.11
    2.3.x        2.6.32 to 3.14
    2.4.x        2.6.32 to 4.0
    2.5.x        2.6.32 to 4.3
    2.6.x        3.10 to 4.7
    2.7.x        3.10 to 4.9
    2.8.x        3.10 to 4.12
    2.9.x        3.10 to 4.13
    2.10.x       3.16 to 4.17
    2.11.x       3.16 to 4.18
    2.12.x       3.16 to 5.0
    2.13.x       3.16 to 5.0
    2.14.x       3.16 to 5.5
    ============ ==============

    Open vSwitch userspace should also work with the Linux kernel module built
    into Linux 3.3 and later.

    Open vSwitch userspace is not sensitive to the Linux kernel version.  It
    should build against almost any kernel, certainly against 2.6.32 and later.

    Open vSwitch branches 2.10 through 2.14 will still compile against the
    RHEL and CentOS 7 3.10 based kernels since they have diverged from the
    Linux kernel.org 3.10 kernels.

Q: Are all features available with all datapaths?

    A: Open vSwitch supports different datapaths on different platforms.  Each
    datapath has a different feature set: the following tables try to summarize
    the status.

    Supported datapaths:

    Linux upstream
      The datapath implemented by the kernel module shipped with Linux
      upstream.  Since features have been gradually introduced into the kernel,
      the table mentions the first Linux release whose OVS module supports the
      feature.

    Linux OVS tree
      The datapath implemented by the Linux kernel module distributed with the
      OVS source tree.

    Userspace
      This datapath supports conventional system devices as well as
      DPDK and AF_XDP devices when support for those is built.  This
      is the only datapath that works on NetBSD, FreeBSD and Mac OSX.

    Hyper-V
      Also known as the Windows datapath.

    The following table lists the datapath supported features from an
    Open vSwitch user's perspective.  The "Linux upstream" column
    lists the Linux kernel version that introduced a given feature
    into its kernel module.  The "Linux OVS tree" and "Userspace"
    columns list the Open vSwitch release versions that introduced a
    given feature into the included kernel module or the userspace
    datapath, respectively.

    ========================== ============== ============== ========= =======
    Feature                    Linux upstream Linux OVS tree Userspace Hyper-V
    ========================== ============== ============== ========= =======
    Connection tracking             4.3            2.5          2.6      YES
    Conntrack Fragment Reass.       4.3            2.6          2.12     YES
    Conntrack Timeout Policies      5.2            2.12         2.14     NO
    Conntrack Zone Limit            4.18           2.10         2.13     YES
    Conntrack NAT                   4.6            2.6          2.8      YES
    Tunnel - LISP                   NO             2.11         NO       NO
    Tunnel - STT                    NO             2.4          NO       YES
    Tunnel - GRE                    3.11           1.0          2.4      YES
    Tunnel - VXLAN                  3.12           1.10         2.4      YES
    Tunnel - Geneve                 3.18           2.4          2.4      YES
    Tunnel - GRE-IPv6               4.18           2.6          2.6      NO
    Tunnel - VXLAN-IPv6             4.3            2.6          2.6      NO
    Tunnel - Geneve-IPv6            4.4            2.6          2.6      NO
    Tunnel - ERSPAN                 4.18           2.10         2.10     NO
    Tunnel - ERSPAN-IPv6            4.18           2.10         2.10     NO
    Tunnel - GTP-U                  NO             NO           2.14     NO
    QoS - Policing                  YES            1.1          2.6      NO
    QoS - Shaping                   YES            1.1          NO       NO
    sFlow                           YES            1.0          1.0      NO
    IPFIX                           3.10           1.11         1.11     YES
    Set action                      YES            1.0          1.0    PARTIAL
    NIC Bonding                     YES            1.0          1.0      YES
    Multiple VTEPs                  YES            1.10         1.10     YES
    Meter action                    4.15           2.10         2.7      NO
    check_pkt_len action            5.2            2.12         2.12     NO
    ========================== ============== ============== ========= =======

    Do note, however:

    * Only a limited set of flow fields is modifiable via the set action by the
      Hyper-V datapath.

    * Userspace datapath support, in some cases, is dependent on the associated
      interface types.  For example, DPDK interfaces support ingress and egress
      policing, but not shaping.

    The following table lists features that do not *directly* impact an Open
    vSwitch user, e.g. because their absence can be hidden by the ofproto layer
    (usually this comes with a performance penalty).

    ===================== ============== ============== ========= =======
    Feature               Linux upstream Linux OVS tree Userspace Hyper-V
    ===================== ============== ============== ========= =======
    SCTP flows            3.12           YES            YES       YES
    MPLS                  3.19           YES            YES       YES
    UFID                  4.0            YES            YES       NO
    Megaflows             3.12           YES            YES       NO
    Masked set action     4.0            YES            YES       NO
    Recirculation         3.19           YES            YES       YES
    TCP flags matching    3.13           YES            YES       NO
    Validate flow actions YES            YES            N/A       NO
    Multiple datapaths    YES            YES            YES       NO
    Tunnel TSO - STT      N/A            YES            NO        YES
    ===================== ============== ============== ========= =======

Q: What DPDK version does each Open vSwitch release work with?

    A: The following table lists the DPDK version against which the given
    versions of Open vSwitch will successfully build.

    ============ ========
    Open vSwitch DPDK
    ============ ========
    2.2.x        1.6
    2.3.x        1.6
    2.4.x        2.0
    2.5.x        2.2
    2.6.x        16.07.2
    2.7.x        16.11.9
    2.8.x        17.05.2
    2.9.x        17.11.10
    2.10.x       17.11.10
    2.11.x       18.11.9
    2.12.x       18.11.9
    2.13.x       19.11.2
    2.14.x       19.11.2
    ============ ========

Q: Are all the DPDK releases that OVS versions work with maintained?

    No. DPDK follows YY.MM.n (Year.Month.Number) versioning.

    Typically, all DPDK releases get a stable YY.MM.1 update with bugfixes 3
    months after the YY.MM.0 release. In some cases there may also be a
    YY.MM.2 release.

    DPDK LTS releases start once a year at YY.11.0 and are maintained for
    two years, with YY.MM.n+1 releases around every 3 months.

    The latest information about DPDK stable and LTS releases can be found
    at `DPDK stable`_.

.. _DPDK stable: http://dpdk.org/doc/guides/contributing/stable.html

Q: I get an error like this when I configure Open vSwitch:

        configure: error: Linux kernel in <dir> is version <x>, but
        version newer than <y> is not supported (please refer to the
        FAQ for advice)

    What should I do?

    A: You have the following options:

    - Use the Linux kernel module supplied with the kernel that you are using.
      (See also the following FAQ.)

    - If there is a newer released version of Open vSwitch, consider building
      that one, because it may support the kernel that you are building
      against.  (To find out, consult the table in the previous FAQ.)

    - The Open vSwitch "master" branch may support the kernel that you are
      using, so consider building the kernel module from "master".

    All versions of Open vSwitch userspace are compatible with all versions of
    the Open vSwitch kernel module, so you do not have to use the kernel module
    from one source along with the userspace programs from the same source.

Q: What features are not available in the Open vSwitch kernel datapath that
ships as part of the upstream Linux kernel?

    A: The kernel module in upstream Linux does not include support for LISP.
    Work is in progress to add support for LISP to the upstream Linux version
    of the Open vSwitch kernel module. For now, if you need this feature, use
    the kernel module from the Open vSwitch distribution instead of the
    upstream Linux kernel module.

    Certain features require kernel support to function or to have reasonable
    performance. If the ovs-vswitchd log file indicates that a feature is not
    supported, consider upgrading to a newer upstream Linux release or using
    the kernel module paired with the userspace distribution.

Q: Why do tunnels not work when using a kernel module other than the one
packaged with Open vSwitch?

    A: Support for tunnels was added to the upstream Linux kernel module after
    the rest of Open vSwitch. As a result, some kernels may contain support for
    Open vSwitch but not tunnels. The minimum kernel version that supports each
    tunnel protocol is:

    ======== ============
    Protocol Linux Kernel
    ======== ============
    GRE      3.11
    VXLAN    3.12
    Geneve   3.18
    ERSPAN   4.18
    LISP     not upstream
    STT      not upstream
    ======== ============

    If you are using a version of the kernel that is older than the one listed
    above, it is still possible to use that tunnel protocol. However, you must
    compile and install the kernel module included with the Open vSwitch
    distribution rather than the one on your machine. If problems persist after
    doing this, check to make sure that the module that is loaded is the one
    you expect.

Q: Why are UDP tunnel checksums not computed for VXLAN or Geneve?

    A: Generating outer UDP checksums requires kernel support that was not part
    of the initial implementation of these protocols. If using the upstream
    Linux Open vSwitch module, you must use kernel 4.0 or newer. The
    out-of-tree modules from Open vSwitch release 2.4 and later support UDP
    checksums.

Q: What features are not available when using the userspace datapath?

    A: Tunnel virtual ports are not supported, as described in the previous
    answer.  It is also not possible to use queue-related actions.  On Linux
    kernels before 2.6.39, maximum-sized VLAN packets may not be transmitted.

Q: Should userspace or kernel be upgraded first to minimize downtime?

    A. In general, the Open vSwitch userspace should be used with the kernel
    version included in the same release or with the version from upstream
    Linux.  However, when upgrading between two releases of Open vSwitch it is
    best to migrate userspace first to reduce the possibility of
    incompatibilities.

Q: What happened to the bridge compatibility feature?

    A: Bridge compatibility was a feature of Open vSwitch 1.9 and earlier.
    When it was enabled, Open vSwitch imitated the interface of the Linux
    kernel "bridge" module.  This allowed users to drop Open vSwitch into
    environments designed to use the Linux kernel bridge module without
    adapting the environment to use Open vSwitch.

    Open vSwitch 1.10 and later do not support bridge compatibility.  The
    feature was dropped because version 1.10 adopted a new internal
    architecture that made bridge compatibility difficult to maintain.  Now
    that many environments use OVS directly, it would be rarely useful in any
    case.

    To use bridge compatibility, install OVS 1.9 or earlier, including the
    accompanying kernel modules (both the main and bridge compatibility
    modules), following the instructions that come with the release.  Be sure
    to start the ovs-brcompatd daemon.
