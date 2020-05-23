## Install P4 compiler

Follow [installation steps](https://github.com/p4lang/p4c#getting-started) for the P4 compiler. 

Please, use my fork of p4c until [this PR](https://github.com/p4lang/p4c/pull/2381) will not be merged:

```
git clone -b ubpf-forwarding https://github.com/osinstom/p4c 
```

## Install OVS from source

Clone this repository and checkout the `v0.1.1` version.

```bash
git checkout v0.1.1
```

.. and follow the standard [installation process](./../../intro/install) for OVS:

```bash
$ ./boot.sh
$ ./configure
$ make && make install
```



