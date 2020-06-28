# Testing

## Unit tests

Every new feature is covered by unit tests. To run tests for P4 use:

```bash
make check TESTSUITEFLAGS='-k p4'
```

Similarily, you can run tests with Valgrind:

```bash
make check-valgrind TESTSUITEFLAGS='-k p4'
```

## PTF tests

[PTF](https://github.com/p4lang/ptf) is a popular tool used by the P4 community to test the functionality of a P4 program.
P4-OvS comes with PTF tests too. However, the initial reason for adding PTF tests was to test P4Runtime functionality. 

First, install PTF:

```bash
git clone https://github.com/p4lang/ptf.git
cd ptf/
sudo python setup.py install
```

Install dependencies:

```
$ pip install --upgrade pip
$ pip install grpcio
```

Setup `veth` interfaces:

```bash
$ sudo ./tests/ptf/veth_setup.sh
```

From `tests/ptf` directory, run PTF tests:

```bash
sudo ./run_ptf.sh
```
