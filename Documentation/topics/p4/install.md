## Install P4 compiler

Follow [installation steps](https://github.com/p4lang/p4c#getting-started) for the P4 compiler. 

## Install PI library

The P4-OvS is based on the [PI](https://github.com/p4lang/PI) library. Please follow [installations steps](https://github.com/p4lang/PI#pi-library-repository) for PI. 

## Install OVS from source

Clone this repository and checkout the `v0.2.0` version.

```bash
git checkout v0.4.0
```

.. and follow the standard [installation process](./../../intro/install) for OVS:

```bash
$ ./boot.sh
$ ./configure
$ make && make install
```



