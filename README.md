# SealPIR: A computational PIR library that achieves low communication costs and high performance.

SealPIR is a (research) library and should not be used in production systems. SealPIR allows a client to download an element from a database stored by a server without revealing which element was downloaded. SealPIR was introduced in our [paper](https://eprint.iacr.org/2017/1142.pdf).


# Compiling SEAL

SealPIR depends on SEAL v2.3.0-4 and a patch that exposes the substitution operator. You can get SEAL v2.3.0-4 from this [link](https://sealcrypto.org).

Once you have downloaded SEAL, apply the patch SEAL_v2.3.0-4.patch (available in this repository) to it. Here are the exact steps. 

We assume that you are in the SEAL directory, and that you have copied the patch to this directory.

First, convert the SEAL directory into a git repo:

```sh
$ git init
$ git add .
$ git commit -m "SEAL v2.3.0-4"
```
Then, apply the patch:

```sh
$ git am SEAL_v2.3.0-4.patch
```

Finally, compile SEAL (NOTE: gcc-8 is not currently supported):

```sh
$ cd SEAL
$ ./configure CXXFLAGS="-O3 -march=native -fPIC"
$ make clean && make
```

# Compiling SealPIR

The current Makefile assumes that SEAL_v2.3.0-4 is located (relative to SealPIR) at: ../SEAL/. If this is not the case change the IDIR and LDIR variables in the Makefile accordingly.

To compile SealPIR simply run ``make``. It should produce a binary file in ``bin/main``.


# Using SealPIR

Take a look at the example in main.cpp for how to use SealPIR.

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
