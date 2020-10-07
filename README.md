![fast-ca logo](https://wille.io/fast-ca.png "fast-ca logo")
# fast-ca

fast-ca is a minimalistic tool to create a local certificate authority and signed certificates in one simple command.
Use fast-ca to ... :

  - rapid prototype a public key encryption protected network
  - create a production ready secured private network with sane default options
  - have your websites in your own network encrypted to prevent password theft
  - and many more ...

### Sane defaults

fast-ca creates private keys with RSA and 4096 bits. The CA's certificate is hashed with SHA-256.
Common name and the DNS field are set to the FQDN, making the generated certificated usable in every (modern) browser.

### Installation

fast-ca requires [botan-2](https://botan.randombit.net/) to compile & run.

Install botan-2:

Ubuntu:
```sh
$ sudo apt install libbotan-2-dev
```

Fedora:
```sh
$ sudo dnf install botan2-devel
```


Use cmake to generate the fast-ca executable & install it on your system:

Ubuntu:
```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

Fedora:
```sh
$ cmake -S . -B build
$ cmake --build build
$ cd build
$ sudo make install
```

### Usage

To create a certificate for a FQDN, just run fast-ca with the FQDN as parameter.

```sh
$ ./fastca test.example.com
```

If you run fast-ca for the first time, a new CA certificate including its corresponding private key is generated prior to generating the client certificate. For the CA private key generation, fast-ca aks for a password to encrypt the private key.

License
----

MIT
