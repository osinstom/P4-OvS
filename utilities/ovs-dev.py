#!/usr/bin/env python3
# Copyright (c) 2013, 2014, 2015, 2016, 2020 Nicira, Inc.
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

import optparse
import os
import shutil
import subprocess
import sys
import time

ENV = os.environ
HOME = ENV["HOME"]
PWD = os.getcwd()
OVS_SRC = HOME + "/ovs"
if os.path.exists(PWD + "/README-original.rst"):
    OVS_SRC = PWD  # Use current directory as OVS source tree
RUNDIR = OVS_SRC + "/_run"
BUILD_GCC = OVS_SRC + "/_build-gcc"
BUILD_CLANG = OVS_SRC + "/_build-clang"

options = None
parser = None
commands = []


def set_path(build):
    PATH = "%(ovs)s/utilities:%(ovs)s/ovsdb:%(ovs)s/vswitchd" % {"ovs": build}

    ENV["PATH"] = PATH + ":" + ENV["PATH"]


def _sh(*args, **kwargs):
    print("------> " + " ".join(args))
    shell = len(args) == 1
    if kwargs.get("capture", False):
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, shell=shell)
        return proc.stdout.readlines()
    elif kwargs.get("check", True):
        subprocess.check_call(args, shell=shell)
    else:
        subprocess.call(args, shell=shell)


def uname():
    return _sh("uname", "-r", capture=True)[0].decode().strip()


def sudo():
    if os.geteuid() != 0:
        _sh(" ".join(["sudo"] + sys.argv), check=True)
        sys.exit(0)


def conf():
    tag()

    try:
        os.remove(OVS_SRC + "/Makefile")
    except OSError:
        pass

    configure = ["../configure",
                 "--prefix=" + RUNDIR, "--localstatedir=" + RUNDIR,
                 "--with-logdir=%s/log" % RUNDIR,
                 "--with-rundir=%s/run" % RUNDIR,
                 "--enable-silent-rules", "--with-dbdir=" + RUNDIR, "--silent"]

    cflags = "-g -fno-omit-frame-pointer"

    if options.werror:
        configure.append("--enable-Werror")

    if options.cache_time:
        configure.append("--enable-cache-time")

    if options.mandir:
        configure.append("--mandir=" + options.mandir)

    if options.with_dpdk:
        configure.append("--with-dpdk=" + options.with_dpdk)
        cflags += " -Wno-cast-align -Wno-bad-function-cast"  # DPDK warnings.

    if options.optimize is None:
        options.optimize = 0

    cflags += " -O%s" % str(options.optimize)

    ENV["CFLAGS"] = cflags

    _sh("./boot.sh")

    try:
        os.mkdir(BUILD_GCC)
    except OSError:
        pass  # Directory exists.

    os.chdir(BUILD_GCC)
    _sh(*(configure + ["--with-linux=/lib/modules/%s/build" % uname()]))

    try:
        _sh("clang --version", check=True)
        clang = True
    except subprocess.CalledProcessError:
        clang = False

    try:
        _sh("sparse --version", check=True)
        sparse = True
    except subprocess.CalledProcessError:
        sparse = False

    if clang:
        try:
            os.mkdir(BUILD_CLANG)
        except OSError:
            pass  # Directory exists.

        ENV["CC"] = "clang"
        os.chdir(BUILD_CLANG)
        _sh(*configure)

    if sparse:
        c1 = "C=1"
    else:
        c1 = ""

    os.chdir(OVS_SRC)

    make_str = "\t$(MAKE) -C %s $@\n"

    mf = open(OVS_SRC + "/Makefile", "w")
    mf.write("all:\n%:\n")
    if clang:
        mf.write(make_str % BUILD_CLANG)
    mf.write("\t$(MAKE) -C %s %s $@\n" % (BUILD_GCC, c1))
    mf.write("\ncheck-valgrind:\n")
    mf.write("\ncheck:\n")
    mf.write(make_str % BUILD_GCC)
    mf.close()


commands.append(conf)


def make(args=""):
    make = "make -s -j 8 " + args
    _sh(make)


commands.append(make)


def check():
    flags = ""
    if options.jobs:
        flags += "-j%d " % options.jobs
    else:
        flags += "-j8 "
    if options.tests:
        for arg in str.split(options.tests):
            if arg[0].isdigit():
                flags += "%s " % arg
            else:
                flags += "-k %s " % arg
    ENV["TESTSUITEFLAGS"] = flags
    make("check")


commands.append(check)


def tag():
    ctags = ['ctags', '-R', '-f', '.tags']

    try:
        _sh(*(ctags + ['--exclude="datapath/"']))
    except:
        try:
            _sh(*ctags)  # Some versions of ctags don't have --exclude
        except:
            pass

    try:
        _sh('cscope', '-R', '-b')
    except:
        pass


commands.append(tag)


def kill():
    sudo()
    for proc in ["ovs-vswitchd", "ovsdb-server"]:
        if os.path.exists("%s/run/openvswitch/%s.pid" % (RUNDIR, proc)):
            _sh("ovs-appctl", "-t", proc, "exit", check=False)
            time.sleep(.1)
        _sh("killall", "-q", "-2", proc, check=False)


commands.append(kill)


def reset():
    sudo()
    kill()
    if os.path.exists(RUNDIR):
        shutil.rmtree(RUNDIR)
    for dp in _sh("ovs-dpctl dump-dps", capture=True):
        _sh("ovs-dpctl", "del-dp", dp.decode().strip())


commands.append(reset)


def run():
    sudo()
    kill()
    for d in ["log", "run"]:
        d = "%s/%s" % (RUNDIR, d)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    pki_dir = RUNDIR + "/pki"
    if not os.path.exists(pki_dir):
        os.mkdir(pki_dir)
        os.chdir(pki_dir)
        _sh("ovs-pki init")
        _sh("ovs-pki req+sign ovsclient")
        os.chdir(OVS_SRC)

    if not os.path.exists(RUNDIR + "/conf.db"):
        _sh("ovsdb-tool", "create", RUNDIR + "/conf.db",
            OVS_SRC + "/vswitchd/vswitch.ovsschema")

    opts = ["--pidfile", "--log-file"]

    if (options.user == "") or (options.user == "root:root"):
        _sh("chown", "root:root", "-R", RUNDIR)
        if '--user' in sys.argv:
            sys.argv.remove("--user")
    else:
        _sh("chown", options.user, "-R", RUNDIR)
        opts = ["--user", options.user] + opts

    if (options.monitor):
        opts = ["--monitor"] + opts

    _sh(*(["ovsdb-server",
           "--remote=punix:%s/run/db.sock" % RUNDIR,
           "--remote=db:Open_vSwitch,Open_vSwitch,manager_options",
           "--private-key=db:Open_vSwitch,SSL,private_key",
           "--certificate=db:Open_vSwitch,SSL,certificate",
           "--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert",
           "--detach", "-vconsole:off"] + opts))

    _sh("ovs-vsctl --no-wait --bootstrap set-ssl %s/ovsclient-privkey.pem"
        " %s/ovsclient-cert.pem %s/vswitchd.cacert"
        % (pki_dir, pki_dir, pki_dir))
    version = _sh("ovs-vsctl --no-wait --version", capture=True)
    version = version[0].decode().strip().split()[3]
    root_uuid = _sh("ovs-vsctl --no-wait --bare list Open_vSwitch",
                    capture=True)[0].decode().strip()
    _sh("ovs-vsctl --no-wait set Open_vSwitch %s ovs_version=%s"
        % (root_uuid, version))

    build = BUILD_CLANG if options.clang else BUILD_GCC
    cmd = [build + "/vswitchd/ovs-vswitchd"]

    if options.dpdk:
        _sh("ovs-vsctl --no-wait set Open_vSwitch %s "
            "other_config:dpdk-init=true" % root_uuid)
        _sh("ovs-vsctl --no-wait set Open_vSwitch %s other_config:"
            "dpdk-extra=\"%s\"" % (root_uuid, ' '.join(options.dpdk)))
    else:
        _sh("ovs-vsctl --no-wait set Open_vSwitch %s "
            "other_config:dpdk-init=false" % root_uuid)

    if options.gdb:
        cmd = ["gdb", "--args"] + cmd
    elif options.valgrind:
        cmd = ["valgrind", "--track-origins=yes", "--leak-check=full",
               "--suppressions=%s/tests/glibc.supp" % OVS_SRC,
               "--suppressions=%s/tests/openssl.supp" % OVS_SRC] + cmd
    else:
        opts = opts + ["-vconsole:off", "--detach", "--enable-dummy"]
    _sh(*(cmd + opts))


commands.append(run)


def modinst():
    if not os.path.exists("/lib/modules"):
        print("Missing modules directory.  Is this a Linux system?")
        sys.exit(1)

    sudo()
    try:
        _sh("rmmod", "openvswitch")
    except subprocess.CalledProcessError:
        pass  # Module isn't loaded

    try:
        _sh("rm -f /lib/modules/%s/extra/openvswitch.ko" % uname())
        _sh("rm -f /lib/modules/%s/extra/vport-*.ko" % uname())
    except subprocess.CalledProcessError:
        pass  # Module isn't installed

    conf()
    make()
    make("modules_install")

    _sh("modprobe", "openvswitch")
    _sh("dmesg | grep openvswitch | tail -1")
    _sh("find /lib/modules/%s/ -iname vport-*.ko -exec insmod '{}' \\;"
        % uname())


commands.append(modinst)


def env():
    print("export PATH=" + ENV["PATH"])


commands.append(env)


def doc():
    parser.print_help()
    print("""
This program is designed to help developers build and run Open vSwitch without
necessarily needing to know the gory details. Given some basic requirements
(described below), it can be used to build and run Open vSwitch, keeping
runtime files in the user's home directory.

Basic Configuration:
    # This section can be run as a script on ubuntu systems.

    # First install the basic requirements needed to build Open vSwitch.
    sudo apt-get install git build-essential libtool autoconf pkg-config \\
            libssl-dev gdb libcap-ng-dev linux-headers-`uname -r`

    # Next clone the Open vSwitch source.
    git clone https://github.com/openvswitch/ovs.git %(ovs)s

    # Setup environment variables.
    `%(v)s env`

    # Build the switch.
    %(v)s conf make

    # Install the kernel module
    sudo insmod %(ovs)s/datapath/linux/openvswitch.ko

    # If needed, manually load all required vport modules:
    sudo insmod %(ovs)s/datapath/linux/vport-vxlan.ko
    sudo insmod %(ovs)s/datapath/linux/vport-geneve.ko
    [...]

    # Run the switch.
    %(v)s run

Commands:
    conf    - Configure the ovs source.
    make    - Build the source (must have been configured).
    check   - Run the unit tests.
    tag     - Run ctags and cscope over the source.
    kill    - Kill all running instances of ovs.
    reset   - Reset any runtime configuration in %(run)s.
    run     - Run ovs.
    modinst - Build ovs and install the kernel module.
    env     - Print the required path environment variable.
    doc     - Print this message.

Note:
    If running as non-root user, "kill", "reset", "run" and "modinst"
    will always run as the root user, by rerun the commands with "sudo".
""" % {"ovs": OVS_SRC, "v": sys.argv[0], "run": RUNDIR})
    sys.exit(0)


commands.append(doc)


def parse_subargs(option, opt_str, value, parser):
    subopts = []

    while parser.rargs:
        dpdkarg = parser.rargs.pop(0)
        if dpdkarg == "--":
            break
        subopts.append(dpdkarg)

    setattr(parser.values, option.dest, subopts)


def main():
    global options
    global parser

    description = "Open vSwitch developer configuration. Try `%prog doc`."
    cmd_names = [c.__name__ for c in commands]
    usage = "usage: %prog" + " [options] [%s] ..." % "|".join(cmd_names)
    parser = optparse.OptionParser(usage=usage, description=description)

    group = optparse.OptionGroup(parser, "conf")
    group.add_option("--disable-Werror", dest="werror", action="store_false",
                     default=True, help="compile without the Werror flag")
    group.add_option("--cache-time", dest="cache_time",
                     action="store_true", help="configure with cached timing")
    group.add_option("--mandir", dest="mandir", metavar="MANDIR",
                     help="configure the man documentation install directory")
    group.add_option("--with-dpdk", dest="with_dpdk", metavar="DPDK_BUILD",
                     help="built with dpdk libraries located at DPDK_BUILD")
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Optimization Flags")
    for i in ["s", "g"] + list(range(4)) + ["fast"]:
        group.add_option("--O%s" % str(i), dest="optimize",
                         action="store_const", const=i,
                         help="compile with -O%s" % str(i))
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "check")
    group.add_option("-j", "--jobs", dest="jobs", metavar="N", type="int",
                     help="Run N tests in parallel")
    group.add_option("--tests", dest="tests", metavar="FILTER",
                     help="""run specific tests and/or a test category
                          eg, --tests=\"1-10 megaflow\"""")
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "run")
    group.add_option("-g", "--gdb", dest="gdb", action="store_true",
                     help="run ovs-vswitchd under gdb")
    group.add_option("--valgrind", dest="valgrind", action="store_true",
                     help="run ovs-vswitchd under valgrind")
    group.add_option("--dpdk", dest="dpdk", action="callback",
                     callback=parse_subargs,
                     help="run ovs-vswitchd with dpdk subopts (ended by --)")
    group.add_option("--clang", dest="clang", action="store_true",
                     help="Use binaries built by clang")
    group.add_option("--user", dest="user", action="store", default="",
                     help="run all daemons as a non root user")
    group.add_option("--monitor", dest="monitor", action="store_true",
                     help="run daemons with --monitor option")

    parser.add_option_group(group)

    options, args = parser.parse_args()

    for arg in args:
        if arg not in cmd_names:
            print("Unknown argument " + arg)
            doc()

    if options.clang:
        set_path(BUILD_CLANG)
    else:
        set_path(BUILD_GCC)

    try:
        os.chdir(OVS_SRC)
    except OSError:
        print("Missing %s." % OVS_SRC)
        doc()

    for arg in args:
        for cmd in commands:
            if arg == cmd.__name__:
                cmd()


if __name__ == '__main__':
    main()
