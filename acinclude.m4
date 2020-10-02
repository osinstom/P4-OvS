# -*- autoconf -*-

# Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2019 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

dnl Set OVS DPCLS Autovalidator as default subtable search at compile time?
dnl This enables automatically running all unit tests with all DPCLS
dnl implementations.
AC_DEFUN([OVS_CHECK_DPCLS_AUTOVALIDATOR], [
  AC_ARG_ENABLE([autovalidator],
                [AC_HELP_STRING([--enable-autovalidator], [Enable DPCLS autovalidator as default subtable search implementation.])],
                [autovalidator=yes],[autovalidator=no])
  AC_MSG_CHECKING([whether DPCLS Autovalidator is default implementation])
  if test "$autovalidator" != yes; then
    AC_MSG_RESULT([no])
  else
    OVS_CFLAGS="$OVS_CFLAGS -DDPCLS_AUTOVALIDATOR_DEFAULT"
    AC_MSG_RESULT([yes])
  fi
])

dnl OVS_ENABLE_WERROR
AC_DEFUN([OVS_ENABLE_WERROR],
  [AC_ARG_ENABLE(
     [Werror],
     [AC_HELP_STRING([--enable-Werror], [Add -Werror to CFLAGS])],
     [], [enable_Werror=no])
   AC_CONFIG_COMMANDS_PRE(
     [if test "X$enable_Werror" = Xyes; then
        OVS_CFLAGS="$OVS_CFLAGS -Werror"
      fi])

   # Unless --enable-Werror is specified, report but do not fail the build
   # for errors reported by flake8.
   if test "X$enable_Werror" = Xyes; then
     FLAKE8_WERROR=
   else
     FLAKE8_WERROR=-
   fi
   AC_SUBST([FLAKE8_WERROR])

   # If --enable-Werror is specified, fail the build on sparse warnings.
   if test "X$enable_Werror" = Xyes; then
     SPARSE_WERROR=-Wsparse-error
   else
     SPARSE_WERROR=
   fi
   AC_SUBST([SPARSE_WERROR])])

dnl OVS_CHECK_LINUX
dnl
dnl Configure linux kernel source tree
AC_DEFUN([OVS_CHECK_LINUX], [
  AC_ARG_WITH([linux],
              [AC_HELP_STRING([--with-linux=/path/to/linux],
                              [Specify the Linux kernel build directory])])
  AC_ARG_WITH([linux-source],
              [AC_HELP_STRING([--with-linux-source=/path/to/linux-source],
                              [Specify the Linux kernel source directory
                               (usually figured out automatically from build
                               directory)])])

  # Deprecated equivalents to --with-linux, --with-linux-source.
  AC_ARG_WITH([l26])
  AC_ARG_WITH([l26-source])

  if test X"$with_linux" != X; then
    KBUILD=$with_linux
  elif test X"$with_l26" != X; then
    KBUILD=$with_l26
    AC_MSG_WARN([--with-l26 is deprecated, please use --with-linux instead])
  else
    KBUILD=
  fi

  if test X"$KBUILD" != X; then
    if test X"$with_linux_source" != X; then
      KSRC=$with_linux_source
    elif test X"$with_l26_source" != X; then
      KSRC=$with_l26_source
      AC_MSG_WARN([--with-l26-source is deprecated, please use --with-linux-source instead])
    else
      KSRC=
    fi
  elif test X"$with_linux_source" != X || test X"$with_l26_source" != X; then
    AC_MSG_ERROR([Linux source directory may not be specified without Linux build directory])
  fi

  if test -n "$KBUILD"; then
    KBUILD=`eval echo "$KBUILD"`
    case $KBUILD in
        /*) ;;
        *) KBUILD=`pwd`/$KBUILD ;;
    esac

    # The build directory is what the user provided.
    # Make sure that it exists.
    AC_MSG_CHECKING([for Linux build directory])
    if test -d "$KBUILD"; then
        AC_MSG_RESULT([$KBUILD])
        AC_SUBST(KBUILD)
    else
        AC_MSG_RESULT([no])
        AC_ERROR([source dir $KBUILD doesn't exist])
    fi

    # Debian breaks kernel headers into "source" header and "build" headers.
    # We want the source headers, but $KBUILD gives us the "build" headers.
    # Use heuristics to find the source headers.
    AC_MSG_CHECKING([for Linux source directory])
    if test -n "$KSRC"; then
      KSRC=`eval echo "$KSRC"`
      case $KSRC in
          /*) ;;
          *) KSRC=`pwd`/$KSRC ;;
      esac
      if test ! -e $KSRC/include/linux/kernel.h; then
        AC_MSG_ERROR([$KSRC is not a kernel source directory])
      fi
    else
      KSRC=$KBUILD
      if test ! -e $KSRC/include/linux/kernel.h; then
        # Debian kernel build Makefiles tend to include a line of the form:
        # MAKEARGS := -C /usr/src/linux-headers-3.2.0-1-common O=/usr/src/linux-headers-3.2.0-1-486
        # First try to extract the source directory from this line.
        KSRC=`sed -n 's/.*-C \([[^ ]]*\).*/\1/p' "$KBUILD"/Makefile`
        if test ! -e "$KSRC"/include/linux/kernel.h; then
          # Didn't work.  Fall back to name-based heuristics that used to work.
          case `echo "$KBUILD" | sed 's,/*$,,'` in # (
            */build)
              KSRC=`echo "$KBUILD" | sed 's,/build/*$,/source,'`
              ;; # (
            *)
              KSRC=`(cd $KBUILD && pwd -P) | sed 's,-[[^-]]*$,-common,'`
              ;;
          esac
        fi
      fi
      if test ! -e "$KSRC"/include/linux/kernel.h; then
        AC_MSG_ERROR([cannot find source directory (please use --with-linux-source)])
      fi
    fi
    AC_MSG_RESULT([$KSRC])

    AC_MSG_CHECKING([for kernel version])
    version=`sed -n 's/^VERSION = //p' "$KSRC/Makefile"`
    patchlevel=`sed -n 's/^PATCHLEVEL = //p' "$KSRC/Makefile"`
    sublevel=`sed -n 's/^SUBLEVEL = //p' "$KSRC/Makefile"`
    if test X"$version" = X || test X"$patchlevel" = X; then
       AC_ERROR([cannot determine kernel version])
    elif test X"$sublevel" = X; then
       kversion=$version.$patchlevel
    else
       kversion=$version.$patchlevel.$sublevel
    fi
    AC_MSG_RESULT([$kversion])

    if test "$version" -ge 5; then
       if test "$version" = 5 && test "$patchlevel" -le 5; then
          : # Linux 5.x
       else
          AC_ERROR([Linux kernel in $KBUILD is version $kversion, but version newer than 5.5.x is not supported (please refer to the FAQ for advice)])
       fi
    elif test "$version" = 4; then
       : # Linux 4.x
    elif test "$version" = 3 && test "$patchlevel" -ge 10; then
       : # Linux 3.x
    else
       AC_ERROR([Linux kernel in $KBUILD is version $kversion, but version 3.10 or later is required])
    fi
    if (test ! -e "$KBUILD"/include/linux/version.h && \
        test ! -e "$KBUILD"/include/generated/uapi/linux/version.h)|| \
       (test ! -e "$KBUILD"/include/linux/autoconf.h && \
        test ! -e "$KBUILD"/include/generated/autoconf.h); then
        AC_MSG_ERROR([Linux kernel source in $KBUILD is not configured])
    fi
    OVS_CHECK_LINUX_COMPAT
  fi
  AM_CONDITIONAL(LINUX_ENABLED, test -n "$KBUILD")
])

dnl OVS_CHECK_LINUX_NETLINK
dnl
dnl Configure Linux netlink compat.
AC_DEFUN([OVS_CHECK_LINUX_NETLINK], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/netlink.h>], [
        struct nla_bitfield32 x =  { 0 };
    ])],
    [AC_DEFINE([HAVE_NLA_BITFIELD32], [1],
    [Define to 1 if struct nla_bitfield32 is available.])])
])

dnl OVS_CHECK_LINUX_TC
dnl
dnl Configure Linux tc compat.
AC_DEFUN([OVS_CHECK_LINUX_TC], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/pkt_cls.h>], [
        int x = TCA_ACT_FLAGS;
    ])],
    [AC_DEFINE([HAVE_TCA_ACT_FLAGS], [1],
               [Define to 1 if TCA_ACT_FLAGS is available.])])

  AC_CHECK_MEMBERS([struct tcf_t.firstuse], [], [], [#include <linux/pkt_cls.h>])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_vlan.h>], [
        int x = TCA_VLAN_PUSH_VLAN_PRIORITY;
    ])],
    [AC_DEFINE([HAVE_TCA_VLAN_PUSH_VLAN_PRIORITY], [1],
               [Define to 1 if TCA_VLAN_PUSH_VLAN_PRIORITY is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_mpls.h>], [
        int x = TCA_MPLS_TTL;
    ])],
    [AC_DEFINE([HAVE_TCA_MPLS_TTL], [1],
               [Define to 1 if HAVE_TCA_MPLS_TTL is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_tunnel_key.h>], [
        int x = TCA_TUNNEL_KEY_ENC_TTL;
    ])],
    [AC_DEFINE([HAVE_TCA_TUNNEL_KEY_ENC_TTL], [1],
               [Define to 1 if TCA_TUNNEL_KEY_ENC_TTL is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_pedit.h>], [
        int x = TCA_PEDIT_KEY_EX_HDR_TYPE_UDP;
    ])],
    [AC_DEFINE([HAVE_TCA_PEDIT_KEY_EX_HDR_TYPE_UDP], [1],
               [Define to 1 if TCA_PEDIT_KEY_EX_HDR_TYPE_UDP is available.])])

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/tc_act/tc_skbedit.h>], [
        int x = TCA_SKBEDIT_FLAGS;
    ])],
    [AC_DEFINE([HAVE_TCA_SKBEDIT_FLAGS], [1],
               [Define to 1 if TCA_SKBEDIT_FLAGS is available.])])
])

dnl OVS_CHECK_LINUX_SCTP_CT
dnl
dnl Checks for kernels which need additional SCTP state
AC_DEFUN([OVS_CHECK_LINUX_SCTP_CT], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_sctp.h>], [
        int x = SCTP_CONNTRACK_HEARTBEAT_SENT;
    ])],
    [AC_DEFINE([HAVE_SCTP_CONNTRACK_HEARTBEATS], [1],
               [Define to 1 if SCTP_CONNTRACK_HEARTBEAT_SENT is available.])])
])

dnl OVS_CHECK_LINUX_VIRTIO_TYPES
dnl
dnl Checks for kernels that need virtio_types definition.
AC_DEFUN([OVS_CHECK_LINUX_VIRTIO_TYPES], [
  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([#include <linux/virtio_types.h>], [
        __virtio16 x =  0;
    ])],
    [AC_DEFINE([HAVE_VIRTIO_TYPES], [1],
    [Define to 1 if __virtio16 is available.])])
])

dnl OVS_FIND_DEPENDENCY(FUNCTION, SEARCH_LIBS, NAME_TO_PRINT)
dnl
dnl Check for a function in a library list.
AC_DEFUN([OVS_FIND_DEPENDENCY], [
  AC_SEARCH_LIBS([$1], [$2], [], [
    AC_MSG_ERROR([unable to find $3, install the dependency package])
  ])
])

dnl OVS_CHECK_LINUX_AF_XDP
dnl
dnl Check both Linux kernel AF_XDP and libbpf support
AC_DEFUN([OVS_CHECK_LINUX_AF_XDP], [
  AC_ARG_ENABLE([afxdp],
                [AC_HELP_STRING([--enable-afxdp], [Enable AF-XDP support])],
                [], [enable_afxdp=no])
  AC_MSG_CHECKING([whether AF_XDP is enabled])
  if test "$enable_afxdp" != yes; then
    AC_MSG_RESULT([no])
    AF_XDP_ENABLE=false
  else
    AC_MSG_RESULT([yes])
    AF_XDP_ENABLE=true

    AC_CHECK_HEADER([bpf/libbpf.h], [],
      [AC_MSG_ERROR([unable to find bpf/libbpf.h for AF_XDP support])])

    AC_CHECK_HEADER([linux/if_xdp.h], [],
      [AC_MSG_ERROR([unable to find linux/if_xdp.h for AF_XDP support])])

    AC_CHECK_HEADER([bpf/xsk.h], [],
      [AC_MSG_ERROR([unable to find bpf/xsk.h for AF_XDP support])])

    AC_CHECK_FUNCS([pthread_spin_lock], [],
      [AC_MSG_ERROR([unable to find pthread_spin_lock for AF_XDP support])])

    OVS_FIND_DEPENDENCY([numa_alloc_onnode], [numa], [libnuma])

    AC_DEFINE([HAVE_AF_XDP], [1],
              [Define to 1 if AF_XDP support is available and enabled.])
    LIBBPF_LDADD=" -lbpf -lelf"
    AC_SUBST([LIBBPF_LDADD])

    AC_CHECK_DECL([xsk_ring_prod__needs_wakeup], [
      AC_DEFINE([HAVE_XDP_NEED_WAKEUP], [1],
        [XDP need wakeup support detected in xsk.h.])
    ], [], [[#include <bpf/xsk.h>]])
  fi
  AM_CONDITIONAL([HAVE_AF_XDP], test "$AF_XDP_ENABLE" = true)
])

dnl OVS_CHECK_DPDK
dnl
dnl Configure DPDK source tree
AC_DEFUN([OVS_CHECK_DPDK], [
  AC_ARG_WITH([dpdk],
              [AC_HELP_STRING([--with-dpdk=/path/to/dpdk],
                              [Specify the DPDK build directory])],
              [have_dpdk=true])

  AC_MSG_CHECKING([whether dpdk is enabled])
  if test "$have_dpdk" != true || test "$with_dpdk" = no; then
    AC_MSG_RESULT([no])
    DPDKLIB_FOUND=false
  else
    AC_MSG_RESULT([yes])
    case "$with_dpdk" in
      yes)
        DPDK_AUTO_DISCOVER="true"
        PKG_CHECK_MODULES_STATIC([DPDK], [libdpdk], [
            DPDK_INCLUDE="$DPDK_CFLAGS"
            DPDK_LIB="$DPDK_LIBS"], [
            DPDK_INCLUDE="-I/usr/local/include/dpdk -I/usr/include/dpdk"
            DPDK_LIB="-ldpdk"])
        ;;
      *)
        DPDK_AUTO_DISCOVER="false"
        DPDK_INCLUDE_PATH="$with_dpdk/include"
        # If 'with_dpdk' is passed install directory, point to headers
        # installed in $DESTDIR/$prefix/include/dpdk
        if test -e "$DPDK_INCLUDE_PATH/rte_config.h"; then
           DPDK_INCLUDE="-I$DPDK_INCLUDE_PATH"
        elif test -e "$DPDK_INCLUDE_PATH/dpdk/rte_config.h"; then
           DPDK_INCLUDE="-I$DPDK_INCLUDE_PATH/dpdk"
        fi
        DPDK_LIB_DIR="$with_dpdk/lib"
        DPDK_LIB="-ldpdk"
        ;;
    esac

    ovs_save_CFLAGS="$CFLAGS"
    ovs_save_LDFLAGS="$LDFLAGS"
    CFLAGS="$CFLAGS $DPDK_INCLUDE"
    if test "$DPDK_AUTO_DISCOVER" = "false"; then
      LDFLAGS="$LDFLAGS -L${DPDK_LIB_DIR}"
    fi

    AC_CHECK_HEADERS([rte_config.h], [], [
      AC_MSG_ERROR([unable to find rte_config.h in $with_dpdk])
    ], [AC_INCLUDES_DEFAULT])

    AC_CHECK_DECLS([RTE_LIBRTE_VHOST_NUMA, RTE_EAL_NUMA_AWARE_HUGEPAGES], [
      OVS_FIND_DEPENDENCY([get_mempolicy], [numa], [libnuma])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_PMD_PCAP], [
      OVS_FIND_DEPENDENCY([pcap_dump_close], [pcap], [libpcap])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_PMD_AF_XDP], [
      LIBBPF_LDADD="-lbpf"
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_VHOST_NUMA], [
      AC_DEFINE([VHOST_NUMA], [1], [NUMA Aware vHost support detected in DPDK.])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_MLX5_PMD], [dnl found
      AC_CHECK_DECL([RTE_IBVERBS_LINK_DLOPEN], [], [dnl not found
        OVS_FIND_DEPENDENCY([mlx5dv_create_wq], [mlx5], [libmlx5])
        OVS_FIND_DEPENDENCY([verbs_init_cq], [ibverbs], [libibverbs])
      ], [[#include <rte_config.h>]])
    ], [], [[#include <rte_config.h>]])

    AC_CHECK_DECL([RTE_LIBRTE_MLX4_PMD], [dnl found
      AC_CHECK_DECL([RTE_IBVERBS_LINK_DLOPEN], [], [dnl not found
        OVS_FIND_DEPENDENCY([mlx4dv_init_obj], [mlx4], [libmlx4])
        OVS_FIND_DEPENDENCY([verbs_init_cq], [ibverbs], [libibverbs])
      ], [[#include <rte_config.h>]])
    ], [], [[#include <rte_config.h>]])

    # DPDK uses dlopen to load plugins.
    OVS_FIND_DEPENDENCY([dlopen], [dl], [libdl])

    AC_MSG_CHECKING([whether linking with dpdk works])
    LIBS="$DPDK_LIB $LIBS"
    AC_LINK_IFELSE(
      [AC_LANG_PROGRAM([#include <rte_config.h>
                        #include <rte_eal.h>],
                       [int rte_argc; char ** rte_argv;
                        rte_eal_init(rte_argc, rte_argv);])],
      [AC_MSG_RESULT([yes])
       DPDKLIB_FOUND=true],
      [AC_MSG_RESULT([no])
       if test "$DPDK_AUTO_DISCOVER" = "true"; then
         AC_MSG_ERROR(m4_normalize([
            Could not find DPDK library in default search path, Use --with-dpdk
            to specify the DPDK library installed in non-standard location]))
       else
         AC_MSG_ERROR([Could not find DPDK libraries in $DPDK_LIB_DIR])
       fi
      ])

    CFLAGS="$ovs_save_CFLAGS"
    LDFLAGS="$ovs_save_LDFLAGS"
    if test "$DPDK_AUTO_DISCOVER" = "false"; then
      OVS_LDFLAGS="$OVS_LDFLAGS -L$DPDK_LIB_DIR"
    fi
    OVS_CFLAGS="$OVS_CFLAGS $DPDK_INCLUDE"
    OVS_ENABLE_OPTION([-mssse3])

    # DPDK pmd drivers are not linked unless --whole-archive is used.
    #
    # This happens because the rest of the DPDK code doesn't use any symbol in
    # the pmd driver objects, and the drivers register themselves using an
    # __attribute__((constructor)) function.
    #
    # These options are specified inside a single -Wl directive to prevent
    # autotools from reordering them.
    #
    # OTOH newer versions of dpdk pkg-config (generated with Meson)
    # will already have flagged just the right set of libs with
    # --whole-archive - in those cases do not wrap it once more.
    case "$DPDK_LIB" in
      *whole-archive*) DPDK_vswitchd_LDFLAGS=$DPDK_LIB;;
      *) DPDK_vswitchd_LDFLAGS=-Wl,--whole-archive,$DPDK_LIB,--no-whole-archive
    esac
    AC_SUBST([DPDK_vswitchd_LDFLAGS])
    AC_DEFINE([DPDK_NETDEV], [1], [System uses the DPDK module.])
  fi

  AM_CONDITIONAL([DPDK_NETDEV], test "$DPDKLIB_FOUND" = true)
])

dnl OVS_GREP_IFELSE(FILE, REGEX, [IF-MATCH], [IF-NO-MATCH])
dnl
dnl Greps FILE for REGEX.  If it matches, runs IF-MATCH, otherwise IF-NO-MATCH.
dnl If IF-MATCH is empty then it defines to OVS_DEFINE(HAVE_<REGEX>), with
dnl <REGEX> translated to uppercase.
AC_DEFUN([OVS_GREP_IFELSE], [
  AC_MSG_CHECKING([whether $2 matches in $1])
  if test -f $1; then
    grep '$2' $1 >/dev/null 2>&1
    status=$?
    case $status in
      0)
        AC_MSG_RESULT([yes])
        m4_if([$3], [], [OVS_DEFINE([HAVE_]m4_toupper([$2]))], [$3])
        ;;
      1)
        AC_MSG_RESULT([no])
        $4
        ;;
      *)
        AC_MSG_ERROR([grep exited with status $status])
        ;;
    esac
  else
    AC_MSG_RESULT([file not found])
    $4
  fi
])

dnl OVS_FIND_FIELD_IFELSE(FILE, STRUCTURE, REGEX, [IF-MATCH], [IF-NO-MATCH])
dnl
dnl Looks for STRUCTURE in FILE. If it is found, greps for REGEX within the
dnl structure definition. If this is successful, runs IF-MATCH, otherwise
dnl IF_NO_MATCH. If IF-MATCH is empty then it defines to
dnl OVS_DEFINE(HAVE_<STRUCTURE>_WITH_<REGEX>), with <STRUCTURE> and <REGEX>
dnl translated to uppercase.
AC_DEFUN([OVS_FIND_FIELD_IFELSE], [
  AC_MSG_CHECKING([whether $2 has member $3 in $1])
  if test -f $1; then
    awk '/$2.{/,/^}/' $1 2>/dev/null | grep '$3' >/dev/null
    status=$?
    case $status in
      0)
        AC_MSG_RESULT([yes])
        m4_if([$4], [], [OVS_DEFINE([HAVE_]m4_toupper([$2])[_WITH_]m4_toupper([$3]))], [$4])
        ;;
      1)
        AC_MSG_RESULT([no])
        $5
        ;;
      *)
        AC_MSG_ERROR([grep exited with status $status])
        ;;
    esac
  else
    AC_MSG_RESULT([file not found])
    $5
  fi
])

dnl OVS_FIND_PARAM_IFELSE(FILE, FUNCTION, REGEX, [IF-MATCH], [IF-NO-MATCH])
dnl
dnl Looks for FUNCTION in FILE. If it is found, greps for REGEX within
dnl the function signature starting from the line matching FUNCTION
dnl and ending with the line containing the closing parenthesis.  If
dnl this is successful, runs IF-MATCH, otherwise IF_NO_MATCH.  If
dnl IF-MATCH is empty then it defines to
dnl OVS_DEFINE(HAVE_<FUNCTION>_WITH_<REGEX>), with <FUNCTION> and
dnl <REGEX> translated to uppercase.
AC_DEFUN([OVS_FIND_PARAM_IFELSE], [
  AC_MSG_CHECKING([whether $2 has parameter $3 in $1])
  if test -f $1; then
    awk '/$2[[ \t\n]]*\(/,/\)/' $1 2>/dev/null | grep '$3' >/dev/null
    status=$?
    case $status in
      0)
        AC_MSG_RESULT([yes])
        m4_if([$4], [], [OVS_DEFINE([HAVE_]m4_toupper([$2])[_WITH_]m4_toupper([$3]))], [$4])
        ;;
      1)
        AC_MSG_RESULT([no])
        $5
        ;;
      *)
        AC_MSG_ERROR([grep exited with status $status])
        ;;
    esac
  else
    AC_MSG_RESULT([file not found])
    $5
  fi
])

dnl OVS_FIND_OP_PARAM_IFELSE(FILE, OP, REGEX, [IF-MATCH], [IF-NO-MATCH])
dnl
dnl Looks for OP in FILE. If it is found, greps for REGEX within the
dnl OP definition. If this is successful, runs IF-MATCH, otherwise
dnl IF_NO_MATCH. If IF-MATCH is empty then it defines to
dnl OVS_DEFINE(HAVE_<OP>_WITH_<REGEX>), with <OP> and <REGEX>
dnl translated to uppercase.
AC_DEFUN([OVS_FIND_OP_PARAM_IFELSE], [
  AC_MSG_CHECKING([whether $2 has member $3 in $1])
  if test -f $1; then
    awk '/$2[[ \t\n]]*\)\(/,/;/' $1 2>/dev/null | grep '$3' >/dev/null
    status=$?
    case $status in
      0)
        AC_MSG_RESULT([yes])
        m4_if([$4], [], [OVS_DEFINE([HAVE_]m4_toupper([$2])[_WITH_]m4_toupper([$3]))], [$4])
        ;;
      1)
        AC_MSG_RESULT([no])
        $5
        ;;
      *)
        AC_MSG_ERROR([grep exited with status $status])
        ;;
    esac
  else
    AC_MSG_RESULT([file not found])
    $5
  fi
])

dnl OVS_DEFINE(NAME)
dnl
dnl Defines NAME to 1 in kcompat.h.
AC_DEFUN([OVS_DEFINE], [
  echo '#define $1 1' >> datapath/linux/kcompat.h.new
])

dnl OVS_CHECK_LINUX_COMPAT
dnl
dnl Runs various Autoconf checks on the Linux kernel source in
dnl the directory in $KBUILD.
AC_DEFUN([OVS_CHECK_LINUX_COMPAT], [
  rm -f datapath/linux/kcompat.h.new
  mkdir -p datapath/linux
  : > datapath/linux/kcompat.h.new

  echo '#include <linux/version.h>
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#define RHEL_RELEASE_VERSION(a, b) 0
#endif' >> datapath/linux/kcompat.h.new

  OVS_GREP_IFELSE([$KSRC/arch/x86/include/asm/checksum_32.h], [src_err,],
                  [OVS_DEFINE([HAVE_CSUM_COPY_DBG])])

  OVS_GREP_IFELSE([$KSRC/include/net/ip6_fib.h], [rt6_get_cookie],
                  [OVS_DEFINE([HAVE_RT6_GET_COOKIE])])

  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/addrconf.h], [ipv6_stub],
                        [dst_entry])
  OVS_GREP_IFELSE([$KSRC/include/net/addrconf.h], [ipv6_dst_lookup.*net],
                  [OVS_DEFINE([HAVE_IPV6_DST_LOOKUP_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/addrconf.h], [ipv6_dst_lookup_flow.*net],
                  [OVS_DEFINE([HAVE_IPV6_DST_LOOKUP_FLOW_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/addrconf.h], [ipv6_stub])
  OVS_GREP_IFELSE([$KSRC/include/net/addrconf.h], [ipv6_dst_lookup_flow])

  OVS_GREP_IFELSE([$KSRC/include/linux/err.h], [ERR_CAST])
  OVS_GREP_IFELSE([$KSRC/include/linux/err.h], [IS_ERR_OR_NULL])
  OVS_GREP_IFELSE([$KSRC/include/linux/err.h], [PTR_ERR_OR_ZERO])

  OVS_GREP_IFELSE([$KSRC/include/linux/jump_label.h], [static_branch_unlikely(],
                  [OVS_DEFINE([HAVE_UPSTREAM_STATIC_KEY])])
  OVS_GREP_IFELSE([$KSRC/include/linux/jump_label.h], [DEFINE_STATIC_KEY_FALSE],
                  [OVS_DEFINE([HAVE_DEFINE_STATIC_KEY])])

  OVS_GREP_IFELSE([$KSRC/include/linux/etherdevice.h], [eth_hw_addr_random])
  OVS_GREP_IFELSE([$KSRC/include/linux/etherdevice.h], [ether_addr_copy])

  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_link.h], [IFLA_GENEVE_TOS])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_link.h], [rtnl_link_stats64])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_link.h], [rtnl_link_stats64])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [vlan_set_encap_proto])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [vlan_hwaccel_push_inside])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [__vlan_hwaccel_clear_tag])

  OVS_GREP_IFELSE([$KSRC/include/linux/in.h], [ipv4_is_multicast])
  OVS_GREP_IFELSE([$KSRC/include/linux/in.h], [proto_ports_offset])
  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [__ip_select_ident.*dst_entry],
                  [OVS_DEFINE([HAVE_IP_SELECT_IDENT_USING_DST_ENTRY])])
  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [__ip_select_ident.*net],
                  [OVS_DEFINE([HAVE_IP_SELECT_IDENT_USING_NET])])

  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [inet_get_local_port_range.*net],
                  [OVS_DEFINE([HAVE_INET_GET_LOCAL_PORT_RANGE_USING_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [ip_defrag.*net],
                  [OVS_DEFINE([HAVE_IP_DEFRAG_TAKES_NET])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/ip.h],
                        [ip_do_fragment], [net],
                        [OVS_DEFINE([HAVE_IP_DO_FRAGMENT_TAKES_NET])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/ip.h],
                        [ip_local_out], [net],
                        [OVS_DEFINE([HAVE_IP_LOCAL_OUT_TAKES_NET])])

  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [ip_skb_dst_mtu])

  OVS_GREP_IFELSE([$KSRC/include/net/ip.h], [IPSKB_FRAG_PMTU],
                  [OVS_DEFINE([HAVE_CORRECT_MRU_HANDLING])])
  OVS_GREP_IFELSE([$KSRC/include/net/ip_tunnels.h], [__ip_tunnel_change_mtu])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [hashfn.*const],
                  [OVS_DEFINE([HAVE_INET_FRAGS_CONST])])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [last_in],
                  [OVS_DEFINE([HAVE_INET_FRAGS_LAST_IN])])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frag_evicting])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frag_evictor])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frags],
                        [frags_work])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frags],
                        [rwlock])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frag_queue],
                        [list_evictor])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frag_lru_move])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/inet_frag.h],
                        [sub_frag_mem_limit], [struct.netns_frags],
                        [OVS_DEFINE([HAVE_SUB_FRAG_MEM_LIMIT_ARG_STRUCT_NETNS_FRAGS])])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [void.*inet_frags_init],
                  [OVS_DEFINE([HAVE_VOID_INET_FRAGS_INIT])])
  OVS_GREP_IFELSE([$KSRC/include/net/inetpeer.h], [vif],
                  [OVS_DEFINE([HAVE_INETPEER_VIF_SUPPORT])])

  dnl Check for dst_cache and ipv6 lable to use backported tunnel infrastructure.
  dnl OVS does not really need ipv6 label field, but its presence signifies that
  dnl the stack has all required ipv6 support.
  dnl OVS also does not need dst_cache But this dependency allows us to write
  dnl much cleaner code.

  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/ip_tunnels.h], [ip_tunnel_key],
                        [label],
                        [OVS_GREP_IFELSE([$KSRC/include/net/ip_tunnels.h],
                                         [iptunnel_pull_offloads],
                        [OVS_GREP_IFELSE([$KSRC/include/net/dst_cache.h], [dst_cache],
                        [OVS_GREP_IFELSE([$KSRC/include/net/erspan.h], [erspan_md2],
                                         [OVS_DEFINE([USE_UPSTREAM_TUNNEL])])])])])

  OVS_GREP_IFELSE([$KSRC/include/net/dst_cache.h], [dst_cache],
                  [OVS_DEFINE([USE_BUILTIN_DST_CACHE])])
  OVS_GREP_IFELSE([$KSRC/include/net/mpls.h], [mpls_hdr],
                  [OVS_DEFINE([MPLS_HEADER_IS_L3])])
  OVS_GREP_IFELSE([$KSRC/include/linux/net.h], [sock_create_kern.*net],
                  [OVS_DEFINE([HAVE_SOCK_CREATE_KERN_NET])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_fill_metadata_dst])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [dev_disable_lro])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [dev_get_stats])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [dev_get_by_index_rcu])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [dev_recursion_level])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [__skb_gso_segment])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [skb_gso_error_unwind])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [can_checksum_protocol])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_get_iflink])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_features_check],
                  [OVS_DEFINE([USE_UPSTREAM_TUNNEL_GSO])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_add_vxlan_port])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_add_geneve_port])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [ndo_udp_tunnel_add])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [netdev_features_t])
  dnl Ubuntu kernel 3.13 has defined this struct but not used for netdev->tstats.
  dnl So check type of tstats.
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [pcpu_sw_netstats.*tstats],
                  [OVS_DEFINE([HAVE_PCPU_SW_NETSTATS])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [netif_needs_gso.*net_device],
                  [OVS_DEFINE([HAVE_NETIF_NEEDS_GSO_NETDEV])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [skb_csum_hwoffload_help])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [udp_offload])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [udp_offload.*uoff],
                  [OVS_DEFINE([HAVE_UDP_OFFLOAD_ARG_UOFF])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [gro_remcsum])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h], [IFF_PHONY_HEADROOM])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device_ops],
                        [extended])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/linux/netdevice.h],
                        [netdev_master_upper_dev_link], [upper_priv],
                        [OVS_DEFINE([HAVE_NETDEV_MASTER_UPPER_DEV_LINK_PRIV])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h],
                  [netdev_master_upper_dev_link_rh],
                  [OVS_DEFINE([HAVE_NETDEV_MASTER_UPPER_DEV_LINK_RH])])

  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device],
                        [max_mtu])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device_ops_extended],
                        [ndo_change_mtu], [OVS_DEFINE([HAVE_RHEL7_MAX_MTU])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/linux/netdevice.h],
                        [dev_change_flags], [extack],
                        [OVS_DEFINE([HAVE_DEV_CHANGE_FLAGS_TAKES_EXTACK])])

  OVS_GREP_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hook_state])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hook_state],
                        [struct net ], [OVS_DEFINE([HAVE_NF_HOOK_STATE_NET])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netfilter.h], [nf_register_net_hook])
  OVS_GREP_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hookfn.*nf_hook_ops],
                  [OVS_DEFINE([HAVE_NF_HOOKFN_ARG_OPS])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hookfn], [priv],
                  [OVS_DEFINE([HAVE_NF_HOOKFN_ARG_PRIV])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hook_ops],
                        [owner], [OVS_DEFINE([HAVE_NF_HOOKS_OPS_OWNER])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netfilter.h], [NFPROTO_INET])
  OVS_GREP_IFELSE([$KSRC/include/linux/netfilter.h], [CONFIG_NF_NAT_NEEDED])


  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netfilter_ipv6.h], [nf_ipv6_ops],
                        [fragment.*sock], [OVS_DEFINE([HAVE_NF_IPV6_OPS_FRAGMENT])])

  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                        [nf_conn], [struct timer_list[[ \t]]*timeout],
                        [OVS_DEFINE([HAVE_NF_CONN_TIMER])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_delete(], [OVS_DEFINE([HAVE_NF_CT_DELETE])])

  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_tmpl_alloc], [nf_conntrack_zone],
                  [OVS_DEFINE([HAVE_NF_CT_TMPL_ALLOC_TAKES_STRUCT_ZONE])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_get_tuplepr], [struct.net],
                  [OVS_DEFINE([HAVE_NF_CT_GET_TUPLEPR_TAKES_STRUCT_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_set])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_is_untracked])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack.h],
                  [nf_ct_invert_tuplepr])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_zones.h],
                  [nf_ct_zone_init])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_l3proto.h],
                  [net_ns_get])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_labels.h],
                  [nf_connlabels_get])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_labels.h],
                  [nf_connlabels_get], [int bit],
                  [OVS_DEFINE([HAVE_NF_CONNLABELS_GET_TAKES_BIT])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_labels.h],
                        [nf_conn_labels], [words])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_nat.h], [nf_ct_nat_ext_add])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_nat.h], [nf_nat_alloc_null_binding])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_nat.h], [nf_nat_range2])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_nat.h], [nf_nat_packet],
                  [OVS_DEFINE([HAVE_UPSTREAM_NF_NAT])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_seqadj.h], [nf_ct_seq_adjust])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_count.h], [nf_conncount_gc_list],
                  [OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_count.h],
                                   [int nf_conncount_add],
                                   [], [OVS_DEFINE([HAVE_UPSTREAM_NF_CONNCOUNT])])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_timeout.h], [nf_ct_set_timeout])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_timeout.h], [struct nf_ct_timeout],
                  [OVS_DEFINE([HAVE_NF_CT_TIMEOUT])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_timeout.h],
                        [\(*nf_ct_timeout_find_get_hook\)], [net],
                        [OVS_DEFINE([HAVE_NF_CT_TIMEOUT_FIND_GET_HOOK_NET])])

  OVS_GREP_IFELSE([$KSRC/include/linux/random.h],
                  [prandom_u32[[\(]]],
                  [OVS_DEFINE([HAVE_PRANDOM_U32])])
  OVS_GREP_IFELSE([$KSRC/include/linux/random.h], [prandom_u32_max])
  OVS_GREP_IFELSE([$KSRC/include/linux/prandom.h],
                  [prandom_u32[[\(]]],
                  [OVS_DEFINE([HAVE_PRANDOM_U32])])
  OVS_GREP_IFELSE([$KSRC/include/linux/prandom.h], [prandom_u32_max])

  OVS_GREP_IFELSE([$KSRC/include/net/rtnetlink.h], [get_link_net])
  OVS_GREP_IFELSE([$KSRC/include/net/rtnetlink.h], [name_assign_type])
  OVS_GREP_IFELSE([$KSRC/include/net/rtnetlink.h], [rtnl_create_link.*src_net],
                  [OVS_DEFINE([HAVE_RTNL_CREATE_LINK_SRC_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/net_namespace.h], [possible_net_t])

  OVS_GREP_IFELSE([$KSRC/include/linux/rcupdate.h], [rcu_read_lock_held], [],
                  [OVS_GREP_IFELSE([$KSRC/include/linux/rtnetlink.h],
                                   [rcu_read_lock_held])])
  OVS_GREP_IFELSE([$KSRC/include/linux/rtnetlink.h], [lockdep_rtnl_is_held])
  OVS_GREP_IFELSE([$KSRC/include/linux/rtnetlink.h], [net_rwsem])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/rtnetlink.h],
                        [rtnl_create_link], [extack],
                        [OVS_DEFINE([HAVE_RTNL_CREATE_LINK_TAKES_EXTACK])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [nf_reset_ct])

  # Check for the proto_data_valid member in struct sk_buff.  The [^@]
  # is necessary because some versions of this header remove the
  # member but retain the kerneldoc comment that describes it (which
  # starts with @).  The brackets must be doubled because of m4
  # quoting rules.
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [[[^@]]proto_data_valid],
                  [OVS_DEFINE([HAVE_PROTO_DATA_VALID])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_checksum_start_offset])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [inner_protocol])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [inner_protocol_type])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_inner_transport_offset])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [kfree_skb_list])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [rxhash])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [u16.*rxhash],
                  [OVS_DEFINE([HAVE_U16_RXHASH])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_dst(],
                  [OVS_DEFINE([HAVE_SKB_DST_ACCESSOR_FUNCS])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [skb_copy_from_linear_data_offset])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [skb_reset_tail_pointer])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_cow_head])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_warn_if_lro],
                  [OVS_DEFINE([HAVE_SKB_WARN_LRO])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [consume_skb])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_frag_page])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_has_frag_list])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [__skb_fill_page_desc])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_reset_mac_len])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_unclone])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_orphan_frags])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_get_hash(],
                  [OVS_DEFINE([HAVE_SKB_GET_HASH])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_clear_hash])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [int.skb_zerocopy(],
                  [OVS_DEFINE([HAVE_SKB_ZEROCOPY])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [u8.*l4_rxhash],
                  [OVS_DEFINE([HAVE_L4_RXHASH])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_ensure_writable])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_vlan_pop])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [__skb_vlan_pop])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_vlan_push])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_clear_hash_if_not_l4])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_postpush_rcsum])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [lco_csum])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_nfct])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_put_zero])

  OVS_GREP_IFELSE([$KSRC/include/linux/types.h], [__wsum],
                  [OVS_DEFINE([HAVE_CSUM_TYPES])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/types.h], [__wsum],
                  [OVS_DEFINE([HAVE_CSUM_TYPES])])

  OVS_GREP_IFELSE([$KSRC/include/net/checksum.h], [csum_replace4])
  OVS_GREP_IFELSE([$KSRC/include/net/checksum.h], [csum_unfold])

  OVS_GREP_IFELSE([$KSRC/include/net/dst.h], [dst_discard_sk])
  OVS_GREP_IFELSE([$KSRC/include/net/dst.h], [__skb_dst_copy])

  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [genl_has_listeners])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [mcgrp_offset])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [parallel_ops])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [netlink_has_listeners(net->genl_sock],
                  [OVS_DEFINE([HAVE_GENL_HAS_LISTENERS_TAKES_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [genlmsg_parse])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [genl_notify.*family],
                  [OVS_DEFINE([HAVE_GENL_NOTIFY_TAKES_FAMILY])])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [genl_validate_flags])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/genetlink.h],
                        [genl_notify], [net],
                        [OVS_DEFINE([HAVE_GENL_NOTIFY_TAKES_NET])])


  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/genetlink.h],
                        [genl_multicast_group], [id])
  OVS_GREP_IFELSE([$KSRC/include/net/geneve.h], [geneve_hdr])

  OVS_GREP_IFELSE([$KSRC/include/net/gre.h], [gre_cisco_register])
  OVS_GREP_IFELSE([$KSRC/include/net/gre.h], [gre_handle_offloads])
  OVS_GREP_IFELSE([$KSRC/include/net/ipv6.h], [IP6_FH_F_SKIP_RH])
  OVS_GREP_IFELSE([$KSRC/include/net/ipv6.h], [ip6_local_out_sk])
  OVS_GREP_IFELSE([$KSRC/include/net/ipv6.h], [__ipv6_addr_jhash])
  OVS_GREP_IFELSE([$KSRC/include/net/ip6_fib.h], [rt6i.*u.dst],
                  [OVS_DEFINE([HAVE_RT6INFO_DST_UNION])])
  OVS_GREP_IFELSE([$KSRC/include/net/ip6_route.h], [ip6_frag.*sock],
                  [OVS_DEFINE([HAVE_IP_FRAGMENT_TAKES_SOCK])])

  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_put_64bit])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_get_be16])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_put_be16])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_put_be32])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_put_be64])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_put_in_addr])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_find_nested])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_is_last])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h], [nla_nest_start_noflag])
  OVS_GREP_IFELSE([$KSRC/include/linux/netlink.h], [void.*netlink_set_err],
                  [OVS_DEFINE([HAVE_VOID_NETLINK_SET_ERR])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netlink.h],
                        [nla_parse], [netlink_ext_ack],
                        [OVS_DEFINE([HAVE_NETLINK_EXT_ACK])])

  OVS_GREP_IFELSE([$KSRC/include/net/sctp/checksum.h], [sctp_compute_cksum])

  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [vlan_insert_tag_set_proto])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [__vlan_insert_tag])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [vlan_get_protocol])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [skb_vlan_tagged])
  OVS_GREP_IFELSE([$KSRC/include/linux/if_vlan.h], [eth_type_vlan])

  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/dst_metadata.h],
                        [metadata_dst_alloc], [metadata_type])

  OVS_GREP_IFELSE([$KSRC/include/linux/u64_stats_sync.h], [u64_stats_fetch_begin_irq])

  OVS_GREP_IFELSE([$KSRC/include/net/vxlan.h], [struct vxlan_metadata],
                  [OVS_DEFINE([HAVE_VXLAN_METADATA])])
  OVS_GREP_IFELSE([$KSRC/include/net/udp.h], [udp_flow_src_port],
                  [OVS_GREP_IFELSE([$KSRC/include/net/udp.h], [inet_get_local_port_range(net],
                                   [OVS_DEFINE([HAVE_UDP_FLOW_SRC_PORT])])])
  OVS_GREP_IFELSE([$KSRC/include/net/udp.h], [udp_v4_check])
  OVS_GREP_IFELSE([$KSRC/include/net/udp_tunnel.h], [udp_tunnel_gro_complete])
  OVS_GREP_IFELSE([$KSRC/include/net/udp_tunnel.h], [sk_buff.*udp_tunnel_handle_offloads],
                  [OVS_DEFINE([HAVE_UDP_TUNNEL_HANDLE_OFFLOAD_RET_SKB])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/udp_tunnel.h], [udp_tunnel_sock_cfg],
                        [gro_receive])

  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [ignore_df],
                  [OVS_DEFINE([HAVE_IGNORE_DF_RENAME])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/netdevice.h], [NET_NAME_UNKNOWN],
                  [OVS_DEFINE([HAVE_NET_NAME_UNKNOWN])])

  OVS_GREP_IFELSE([$KSRC/include/net/sock.h], [sk_no_check_tx])
  OVS_GREP_IFELSE([$KSRC/include/linux/udp.h], [no_check6_tx])
  OVS_GREP_IFELSE([$KSRC/include/linux/utsrelease.h], [el6],
                  [OVS_DEFINE([HAVE_RHEL6_PER_CPU])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/protocol.h],
                        [udp_add_offload], [net],
                        [OVS_DEFINE([HAVE_UDP_ADD_OFFLOAD_TAKES_NET])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/ipv6/nf_defrag_ipv6.h],
                        [nf_defrag_ipv6_enable], [net],
                        [OVS_DEFINE([HAVE_DEFRAG_ENABLE_TAKES_NET])])
  OVS_GREP_IFELSE([$KSRC/include/net/genetlink.h], [family_list],
                        [OVS_DEFINE([HAVE_GENL_FAMILY_LIST])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device],
                        [needs_free_netdev],
                        [OVS_DEFINE([HAVE_NEEDS_FREE_NETDEV])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/vxlan.h], [vxlan_dev], [cfg],
                        [OVS_DEFINE([HAVE_VXLAN_DEV_CFG])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_helper.h],
                  [nf_conntrack_helper_put],
                  [OVS_DEFINE(HAVE_NF_CONNTRACK_HELPER_PUT)])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_helper.h],
                  [nf_nat_helper_try_module_get])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_helper.h],
                  [nf_nat_helper_put])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],[[[[:space:]]]SKB_GSO_UDP[[[:space:]]]],
                  [OVS_DEFINE([HAVE_SKB_GSO_UDP])])
  OVS_GREP_IFELSE([$KSRC/include/net/dst.h],[DST_NOCACHE],
                  [OVS_DEFINE([HAVE_DST_NOCACHE])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/rtnetlink.h], [rtnl_link_ops],
                        [extack],
                  [OVS_DEFINE([HAVE_EXT_ACK_IN_RTNL_LINKOPS])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netfilter.h], [nf_hook_ops],
                        [list],
                        [OVS_DEFINE([HAVE_LIST_IN_NF_HOOK_OPS])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/netfilter/nf_conntrack_common.h],
                  [IP_CT_UNTRACKED])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/linux/netdevice.h],
                        [netdev_master_upper_dev_link], [extack],
                        [OVS_DEFINE([HAVE_UPPER_DEV_LINK_EXTACK])])
  OVS_GREP_IFELSE([$KSRC/include/linux/compiler_types.h],
                  [__LINUX_COMPILER_TYPES_H],
                  [OVS_DEFINE([HAVE_LINUX_COMPILER_TYPES_H])])
  OVS_GREP_IFELSE([$KSRC/include/linux/timekeeping.h],
                  [ktime_get_ts64],
                  [OVS_DEFINE([HAVE_KTIME_GET_TS64])])
  OVS_GREP_IFELSE([$KSRC/include/net/net_namespace.h],
                  [EXPORT_SYMBOL_GPL(peernet2id_alloc)],
                  [OVS_DEFINE([HAVE_PEERNET2ID_ALLOC])])
  OVS_GREP_IFELSE([$KSRC/include/linux/timekeeping.h],
                  [ktime_get_ns],
                  [OVS_DEFINE([HAVE_KTIME_GET_NS])])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h],
                  frag_percpu_counter_batch[],
                  [OVS_DEFINE([HAVE_FRAG_PERCPU_COUNTER_BATCH])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [null_compute_pseudo],
                  [OVS_DEFINE([HAVE_NULL_COMPUTE_PSEUDO])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [__skb_checksum_convert],
                  [OVS_DEFINE([HAVE_SKB_CHECKSUM_CONVERT])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device],
                        [max_mtu],
                        [OVS_DEFINE([HAVE_NET_DEVICE_MAX_MTU])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/ip6_tunnel.h], [__ip6_tnl_parm],
                        [erspan_ver],
                        [OVS_DEFINE([HAVE_IP6_TNL_PARM_ERSPAN_VER])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [SKB_GSO_IPXIP6],
                  [OVS_DEFINE([HAVE_SKB_GSO_IPXIP6])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/ipv6.h],
                        [ip6_make_flowlabel], [fl6],
                        [OVS_DEFINE([HAVE_IP6_MAKE_FLOWLABEL_FL6])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/ipv6.h], [netns_sysctl_ipv6],
                        [auto_flowlabels],
                        [OVS_DEFINE([HAVE_NETNS_SYSCTL_IPV6_AUTO_FLOWLABELS])])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h],
                  [netif_keep_dst],
                  [OVS_DEFINE([HAVE_NETIF_KEEP_DST])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/netdevice.h], [net_device_ops],
                        [ndo_get_iflink],
                        [OVS_DEFINE([HAVE_NDO_GET_IFLINK])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [skb_set_inner_ipproto],
                  [OVS_DEFINE([HAVE_SKB_SET_INNER_IPPROTO])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [tunnel_encap_types],
                  [OVS_DEFINE([HAVE_TUNNEL_ENCAP_TYPES])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_IPTUN_ENCAP_TYPE],
                  [OVS_DEFINE([HAVE_IFLA_IPTUN_ENCAP_TYPE])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_IPTUN_COLLECT_METADATA],
                  [OVS_DEFINE([HAVE_IFLA_IPTUN_COLLECT_METADATA])])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_ENCAP_DPORT])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_COLLECT_METADATA])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_IGNORE_DF])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_FWMARK])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_ERSPAN_INDEX])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_GRE_ERSPAN_HWID])
  OVS_GREP_IFELSE([$KSRC/include/uapi/linux/if_tunnel.h],
                  [IFLA_IPTUN_FWMARK])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/skbuff.h], [sk_buff],
                        [csum_valid],
                        [OVS_DEFINE([HAVE_SKBUFF_CSUM_VALID])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/linux/skbuff.h], [sk_buff],
                        [vlan_present],
                        [OVS_DEFINE([HAVE_SKBUFF_VLAN_PRESENT])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [skb_checksum_simple_validate])
  OVS_GREP_IFELSE([$KSRC/include/linux/netdevice.h],
                  [void.*ndo_get_stats64],
                  [OVS_DEFINE([HAVE_VOID_NDO_GET_STATS64])])
  OVS_GREP_IFELSE([$KSRC/include/linux/timer.h], [init_timer_deferrable],
                  [OVS_DEFINE([HAVE_INIT_TIMER_DEFERRABLE])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/ip_tunnels.h],
                        [ip_tunnel_info_opts_set], [flags],
                        [OVS_DEFINE([HAVE_IP_TUNNEL_INFO_OPTS_SET_FLAGS])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/inet_frag.h], [inet_frags],
                        [rnd],
                        [OVS_DEFINE([HAVE_INET_FRAGS_RND])])
  OVS_GREP_IFELSE([$KSRC/include/linux/overflow.h], [__LINUX_OVERFLOW_H],
                  [OVS_DEFINE([HAVE_OVERFLOW_H])])
  OVS_GREP_IFELSE([$KSRC/include/linux/overflow.h], [struct_size],
                  [OVS_DEFINE([HAVE_STRUCT_SIZE])])
  OVS_GREP_IFELSE([$KSRC/include/linux/mm.h], [kvmalloc_array],
                  [OVS_DEFINE([HAVE_KVMALLOC_ARRAY])])
  OVS_GREP_IFELSE([$KSRC/include/linux/mm.h], [kvmalloc_node],
                  [OVS_DEFINE([HAVE_KVMALLOC_NODE])])
  OVS_GREP_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_l3proto.h],
                  [nf_conntrack_l3proto],
                  [OVS_DEFINE([HAVE_NF_CONNTRACK_L3PROATO_H])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_core.h],
                        [nf_conntrack_in], [nf_hook_state],
                        [OVS_DEFINE([HAVE_NF_CONNTRACK_IN_TAKES_NF_HOOK_STATE])])
  OVS_GREP_IFELSE([$KSRC/include/net/ipv6_frag.h], [IP6_DEFRAG_CONNTRACK_IN],
                  [OVS_DEFINE([HAVE_IPV6_FRAG_H])])
  OVS_FIND_PARAM_IFELSE([$KSRC/include/net/netfilter/nf_conntrack_helper.h],
                        [nf_ct_helper_ext_add], [nf_conntrack_helper],
                        [OVS_DEFINE([HAVE_NF_CT_HELPER_EXT_ADD_TAKES_HELPER])])
  OVS_GREP_IFELSE([$KSRC/include/net/gre.h], [gre_calc_hlen],
                  [OVS_DEFINE([HAVE_GRE_CALC_HLEN])])
  OVS_GREP_IFELSE([$KSRC/include/net/gre.h], [ip_gre_calc_hlen],
                  [OVS_DEFINE([HAVE_IP_GRE_CALC_HLEN])])
  OVS_GREP_IFELSE([$KSRC/include/linux/rbtree.h], [rb_link_node_rcu],
                  [OVS_DEFINE([HAVE_RBTREE_RB_LINK_NODE_RCU])])
  OVS_GREP_IFELSE([$KSRC/include/net/dst_ops.h], [bool confirm_neigh],
                  [OVS_DEFINE([HAVE_DST_OPS_CONFIRM_NEIGH])])
  OVS_GREP_IFELSE([$KSRC/include/net/inet_frag.h], [fqdir],
                  [OVS_DEFINE([HAVE_INET_FRAG_FQDIR])])
  OVS_FIND_FIELD_IFELSE([$KSRC/include/net/genetlink.h], [genl_ops],
                        [policy],
                        [OVS_DEFINE([HAVE_GENL_OPS_POLICY])])
  OVS_GREP_IFELSE([$KSRC/include/net/netlink.h],
                  [nla_parse_deprecated_strict],
                  [OVS_DEFINE([HAVE_NLA_PARSE_DEPRECATED_STRICT])])
  OVS_FIND_OP_PARAM_IFELSE([$KSRC/include/net/rtnetlink.h],
                           [validate], [extack],
                           [OVS_DEFINE([HAVE_RTNLOP_VALIDATE_WITH_EXTACK])])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h],
                  [__skb_set_hash])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [sw_hash])
  OVS_GREP_IFELSE([$KSRC/include/linux/skbuff.h], [skb_get_hash_raw])

  if cmp -s datapath/linux/kcompat.h.new \
            datapath/linux/kcompat.h >/dev/null 2>&1; then
    rm datapath/linux/kcompat.h.new
  else
    mv datapath/linux/kcompat.h.new datapath/linux/kcompat.h
  fi
])

dnl Checks for net/if_dl.h.
dnl
dnl (We use this as a proxy for checking whether we're building on FreeBSD
dnl or NetBSD.)
AC_DEFUN([OVS_CHECK_IF_DL],
  [AC_CHECK_HEADER([net/if_dl.h],
                   [HAVE_IF_DL=yes],
                   [HAVE_IF_DL=no])
   AM_CONDITIONAL([HAVE_IF_DL], [test "$HAVE_IF_DL" = yes])
   if test "$HAVE_IF_DL" = yes; then
      AC_DEFINE([HAVE_IF_DL], [1],
                [Define to 1 if net/if_dl.h is available.])

      # On these platforms we use libpcap to access network devices.
      AC_SEARCH_LIBS([pcap_open_live], [pcap])
   fi])

dnl Checks for buggy strtok_r.
dnl
dnl Some versions of glibc 2.7 has a bug in strtok_r when compiling
dnl with optimization that can cause segfaults:
dnl
dnl http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
AC_DEFUN([OVS_CHECK_STRTOK_R],
  [AC_CACHE_CHECK(
     [whether strtok_r macro segfaults on some inputs],
     [ovs_cv_strtok_r_bug],
     [AC_RUN_IFELSE(
        [AC_LANG_PROGRAM([#include <stdio.h>
                          #include <string.h>
                         ],
                         [[#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 8
                           /* Assume bug is present, because relatively minor
                              changes in compiler settings (e.g. optimization
                              level) can make it crop up. */
                           return 1;
                           #else
                           char string[] = ":::";
                           char *save_ptr = (char *) 0xc0ffee;
                           char *token1, *token2;
                           token1 = strtok_r(string, ":", &save_ptr);
                           token2 = strtok_r(NULL, ":", &save_ptr);
                           freopen ("/dev/null", "w", stdout);
                           printf ("%s %s\n", token1, token2);
                           return 0;
                           #endif
                          ]])],
        [ovs_cv_strtok_r_bug=no],
        [ovs_cv_strtok_r_bug=yes],
        [ovs_cv_strtok_r_bug=yes])])
   if test $ovs_cv_strtok_r_bug = yes; then
     AC_DEFINE([HAVE_STRTOK_R_BUG], [1],
               [Define if strtok_r macro segfaults on some inputs])
   fi
])

dnl ----------------------------------------------------------------------
dnl These macros are from GNU PSPP, with the following original license:
dnl Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([_OVS_CHECK_CC_OPTION], [dnl
  m4_define([ovs_cv_name], [ovs_cv_[]m4_translit([$1], [-= ], [__])])dnl
  AC_CACHE_CHECK([whether $CC accepts $1], [ovs_cv_name], 
    [ovs_save_CFLAGS="$CFLAGS"
     dnl Include -Werror in the compiler options, because without -Werror
     dnl clang's GCC-compatible compiler driver does not return a failure
     dnl exit status even though it complains about options it does not
     dnl understand.
     dnl
     dnl Also, check stderr as gcc exits with status 0 for options
     dnl rejected at getopt level.
     dnl    % touch /tmp/a.c
     dnl    % gcc -g -c -Werror -Qunused-arguments /tmp/a.c; echo $?
     dnl    gcc: unrecognized option '-Qunused-arguments'
     dnl    0
     dnl    %
     dnl
     dnl In addition, GCC does not complain about a -Wno-<foo> option that
     dnl it does not understand, unless it has another error to report, so
     dnl instead of testing for -Wno-<foo>, test for the positive version.
     CFLAGS="$CFLAGS $WERROR m4_bpatsubst([$1], [-Wno-], [-W])"
     AC_COMPILE_IFELSE(
       [AC_LANG_SOURCE([int x;])],
       [if test -s conftest.err && grep "unrecognized option" conftest.err
        then
          ovs_cv_name[]=no
        else
          ovs_cv_name[]=yes
        fi],
       [ovs_cv_name[]=no])
     CFLAGS="$ovs_save_CFLAGS"])
  if test $ovs_cv_name = yes; then
    m4_if([$2], [], [:], [$2])
  else
    m4_if([$3], [], [:], [$3])
  fi
])

dnl OVS_CHECK_WERROR
dnl
dnl Check whether the C compiler accepts -Werror.
dnl Sets $WERROR to "-Werror", if so, and otherwise to the empty string.
AC_DEFUN([OVS_CHECK_WERROR],
  [WERROR=
   _OVS_CHECK_CC_OPTION([-Werror], [WERROR=-Werror])])

dnl OVS_CHECK_CC_OPTION([OPTION], [ACTION-IF-ACCEPTED], [ACTION-IF-REJECTED])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, execute ACTION-IF-ACCEPTED, otherwise ACTION-IF-REJECTED.
AC_DEFUN([OVS_CHECK_CC_OPTION],
  [AC_REQUIRE([OVS_CHECK_WERROR])
   _OVS_CHECK_CC_OPTION([$1], [$2], [$3])])

dnl OVS_ENABLE_OPTION([OPTION])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, add it to WARNING_FLAGS.
dnl Example: OVS_ENABLE_OPTION([-Wdeclaration-after-statement])
AC_DEFUN([OVS_ENABLE_OPTION], 
  [OVS_CHECK_CC_OPTION([$1], [WARNING_FLAGS="$WARNING_FLAGS $1"])
   AC_SUBST([WARNING_FLAGS])])

dnl OVS_CONDITIONAL_CC_OPTION([OPTION], [CONDITIONAL])
dnl Check whether the given C compiler OPTION is accepted.
dnl If so, enable the given Automake CONDITIONAL.

dnl Example: OVS_CONDITIONAL_CC_OPTION([-Wno-unused], [HAVE_WNO_UNUSED])
AC_DEFUN([OVS_CONDITIONAL_CC_OPTION],
  [OVS_CHECK_CC_OPTION(
    [$1], [ovs_have_cc_option=yes], [ovs_have_cc_option=no])
   AM_CONDITIONAL([$2], [test $ovs_have_cc_option = yes])])
dnl ----------------------------------------------------------------------

dnl Check for too-old XenServer.
AC_DEFUN([OVS_CHECK_XENSERVER_VERSION],
  [AC_CACHE_CHECK([XenServer release], [ovs_cv_xsversion],
    [if test -e /etc/redhat-release; then
       ovs_cv_xsversion=`sed -n 's/^XenServer DDK release \([[^-]]*\)-.*/\1/p' /etc/redhat-release`
     fi
     if test -z "$ovs_cv_xsversion"; then
       ovs_cv_xsversion=none
     fi])
  case $ovs_cv_xsversion in
    none)
      ;;

    [[1-9]][[0-9]]* |                    dnl XenServer 10 or later
    [[6-9]]* |                           dnl XenServer 6 or later
    5.[[7-9]]* |                         dnl XenServer 5.7 or later
    5.6.[[1-9]][[0-9]][[0-9]][[0-9]]* |  dnl XenServer 5.6.1000 or later
    5.6.[[2-9]][[0-9]][[0-9]]* |         dnl XenServer 5.6.200 or later
    5.6.1[[0-9]][[0-9]])                 dnl Xenserver 5.6.100 or later
      ;;

    *)
      AC_MSG_ERROR([This appears to be XenServer $ovs_cv_xsversion, but only XenServer 5.6.100 or later is supported.  (If you are really using a supported version of XenServer, you may override this error message by specifying 'ovs_cv_xsversion=5.6.100' on the "configure" command line.)])
      ;;
  esac])

dnl OVS_CHECK_SPARSE_TARGET
dnl
dnl The "cgcc" script from "sparse" isn't very good at detecting the
dnl target for which the code is being built.  This helps it out.
AC_DEFUN([OVS_CHECK_SPARSE_TARGET],
  [AC_CACHE_CHECK(
    [target hint for cgcc],
    [ac_cv_sparse_target],
    [AS_CASE([`$CC -dumpmachine 2>/dev/null`],
       [i?86-* | athlon-*], [ac_cv_sparse_target=x86],
       [x86_64-*], [ac_cv_sparse_target=x86_64],
       [ac_cv_sparse_target=other])])
   AS_CASE([$ac_cv_sparse_target],
     [x86], [SPARSEFLAGS= CGCCFLAGS="-target=i86 -target=host_os_specs"],
     [x86_64], [SPARSEFLAGS=-m64 CGCCFLAGS="-target=x86_64 -target=host_os_specs"],
     [SPARSEFLAGS= CGCCFLAGS=])

   dnl Get the default defines for vector instructions from compiler to
   dnl allow "sparse" correctly check the same code that will be built.
   dnl Required for checking DPDK headers.
   AC_MSG_CHECKING([vector options for cgcc])
   VECTOR=$($CC -dM -E - < /dev/null | grep -E "MMX|SSE|AVX" | \
            cut -c 9- | sed 's/ /=/' | sed 's/^/-D/' | tr '\n' ' ')
   AC_MSG_RESULT([$VECTOR])
   CGCCFLAGS="$CGCCFLAGS $VECTOR"

   AC_SUBST([SPARSEFLAGS])
   AC_SUBST([CGCCFLAGS])])

dnl OVS_SPARSE_EXTRA_INCLUDES
dnl
dnl The cgcc script from "sparse" does not search gcc's default
dnl search path. Get the default search path from GCC and pass
dnl them to sparse.
AC_DEFUN([OVS_SPARSE_EXTRA_INCLUDES],
    AC_SUBST([SPARSE_EXTRA_INCLUDES],
           [`$CC -v -E - </dev/null 2>&1 >/dev/null | sed -n -e '/^#include.*search.*starts.*here:/,/^End.*of.*search.*list\./s/^ \(.*\)/-I \1/p' |grep -v /usr/lib | grep -x -v '\-I /usr/include' | tr \\\n ' ' `] ))

dnl OVS_ENABLE_SPARSE
AC_DEFUN([OVS_ENABLE_SPARSE],
  [AC_REQUIRE([OVS_CHECK_SPARSE_TARGET])
   AC_REQUIRE([OVS_SPARSE_EXTRA_INCLUDES])
   : ${SPARSE=sparse}
   AC_SUBST([SPARSE])
   AC_CONFIG_COMMANDS_PRE(
     [CC='$(if $(C:0=),env REAL_CC="'"$CC"'" CHECK="$(SPARSE) $(SPARSE_WERROR) -I $(top_srcdir)/include/sparse $(SPARSEFLAGS) $(SPARSE_EXTRA_INCLUDES) " cgcc $(CGCCFLAGS),'"$CC"')'])

   AC_ARG_ENABLE(
     [sparse],
     [AC_HELP_STRING([--enable-sparse], [Run "sparse" by default])],
     [], [enable_sparse=no])
   AM_CONDITIONAL([ENABLE_SPARSE_BY_DEFAULT], [test $enable_sparse = yes])])

dnl OVS_CTAGS_IDENTIFIERS
dnl
dnl ctags ignores symbols with extras identifiers. This is a list of
dnl specially handled identifiers to be ignored. [ctags(1) -I <list>].
AC_DEFUN([OVS_CTAGS_IDENTIFIERS],
    AC_SUBST([OVS_CTAGS_IDENTIFIERS_LIST],
           ["OVS_LOCKABLE OVS_NO_THREAD_SAFETY_ANALYSIS OVS_REQ_RDLOCK+ OVS_ACQ_RDLOCK+ OVS_REQ_WRLOCK+ OVS_ACQ_WRLOCK+ OVS_REQUIRES+ OVS_ACQUIRES+ OVS_TRY_WRLOCK+ OVS_TRY_RDLOCK+ OVS_TRY_LOCK+ OVS_GUARDED_BY+ OVS_EXCLUDED+ OVS_RELEASES+ OVS_ACQ_BEFORE+ OVS_ACQ_AFTER+"]))

dnl OVS_PTHREAD_SET_NAME
dnl
dnl This checks for three known variants of pthreads functions for setting
dnl the name of the current thread:
dnl
dnl   glibc: int pthread_setname_np(pthread_t, const char *name);
dnl   NetBSD: int pthread_setname_np(pthread_t, const char *format, void *arg);
dnl   FreeBSD: int pthread_set_name_np(pthread_t, const char *name);
dnl
dnl For glibc and FreeBSD, the arguments are just a thread and its name.  For
dnl NetBSD, 'format' is a printf() format string and 'arg' is an argument to
dnl provide to it.
dnl
dnl This macro defines:
dnl
dnl    glibc: HAVE_GLIBC_PTHREAD_SETNAME_NP
dnl    NetBSD: HAVE_NETBSD_PTHREAD_SETNAME_NP
dnl    FreeBSD: HAVE_PTHREAD_SET_NAME_NP
AC_DEFUN([OVS_CHECK_PTHREAD_SET_NAME],
  [AC_CHECK_FUNCS([pthread_set_name_np])
   if test $ac_cv_func_pthread_set_name_np != yes; then
     AC_CACHE_CHECK(
       [for pthread_setname_np() variant],
       [ovs_cv_pthread_setname_np],
       [AC_LINK_IFELSE(
         [AC_LANG_PROGRAM([#include <pthread.h>
  ], [pthread_setname_np(pthread_self(), "name");])],
         [ovs_cv_pthread_setname_np=glibc],
         [AC_LINK_IFELSE(
           [AC_LANG_PROGRAM([#include <pthread.h>
], [pthread_setname_np(pthread_self(), "%s", "name");])],
           [ovs_cv_pthread_setname_np=netbsd],
           [ovs_cv_pthread_setname_np=none])])])
     case $ovs_cv_pthread_setname_np in # (
       glibc)
          AC_DEFINE(
            [HAVE_GLIBC_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 2 parameters (like glibc).])
          ;; # (
       netbsd)
          AC_DEFINE(
            [HAVE_NETBSD_PTHREAD_SETNAME_NP], [1],
            [Define to 1 if pthread_setname_np() is available and takes 3 parameters (like NetBSD).])
          ;;
     esac
   fi])

dnl OVS_CHECK_LINUX_HOST.
dnl
dnl Checks whether we're building for a Linux host, based on the presence of
dnl the __linux__ preprocessor symbol, and sets up an Automake conditional
dnl LINUX based on the result.
AC_DEFUN([OVS_CHECK_LINUX_HOST],
  [AC_CACHE_CHECK(
     [whether __linux__ is defined],
     [ovs_cv_linux],
     [AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([enum { LINUX = __linux__};], [])],
        [ovs_cv_linux=true],
        [ovs_cv_linux=false])])
   AM_CONDITIONAL([LINUX], [$ovs_cv_linux])])
