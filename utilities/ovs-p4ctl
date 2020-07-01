#! /usr/bin/python3
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

"""
ovs-p4ctl utility allows to control P4 bridges.
"""

import argparse
import sys

USAGE = "ovs-p4ctl: P4Runtime switch management utility\n"

def usage():
    print (USAGE + """\
adsada

The following options are also available:
  -h, --help                  display this help message
""")
# % {'argv0': argv0})
    sys.exit(0)

def main():
    if len(sys.argv) < 2:
       print("ovs-p4ctl: missing command name; use --help for help")
       sys.exit(1)
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument('add-pipe', help='inserts P4 program to the switch')
    parser.add_argument('get-pipe', help='gets current P4 program from the switch')

    args = parser.parse_args(sys.argv[1:2])
    if not hasattr(self, args.command):
        print("Unrecognized command")
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()

# Local variables:
# mode: python
# End: