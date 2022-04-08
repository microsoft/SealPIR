# SealPIR: A computational PIR library that achieves low communication costs and high performance.

SealPIR is a research library and should not be used in production systems. 
SealPIR allows a client to download an element from a database stored by a server without
revealing to the server which element was downloaded. SealPIR was introduced at 
the IEEE Symposium on Security and Privacy (Oakland) in 2018. You can find
a copy of the paper [here](https://eprint.iacr.org/2017/1142.pdf).

# Compiling SEAL

SealPIR depends on [Microsoft SEAL version 4.0.0](https://github.com/microsoft/SEAL/tree/4.0.0).

Download and install SEAL (follow the instructions in the above link) before before compiling SealPIR.

# Compiling SealPIR

Once Microsoft SEAL 4.0.0 is installed, to build SealPIR simply run:

```
cmake .
make
```

This should produce a binary file ``bin/main``.

# Testing SealPIR

Once you have compiled SealPIR, you can run our battery of unit tests with:

```
ctest .
```

# Using SealPIR

Take a look at the example in `src/main.cpp` for how to use SealPIR. 
You can also look at the tests in the `test` folder.


## Default parameters

*N* indicates the degree of the BFV polynomials.  Default is 4096.

*t* indicates the plaintext modulus, but we specify *log t* instead. Default is 20.

Each BFV ciphertext can encrypt log t * N, which is approximately 10 KB bits of information.

This means that if your database has, say, 1 KB elements, then you can pack 10 
such elements into a single BFV plaintext. 
On the other hand, if your database has, say, 20 KB elements, then you will 
need two BFV plaintexts to represent each of your elements.

*d* represents the recursion level.  When the number of BFV plaintexts needed
to represent your database (see above for how to map the number of database
elements of a given size to the number of BFV plaintexts) is smaller than N,
then setting *d = 1* minimizes communication costs. However, you can also set
*d = 2* which doubles the size of the query and increases the size of the
response by roughly a factor of 4, but in some cases might reduce computational
costs a little bit (because the oblivious expansion procedure is cheaper). 

When the number of BFV plaintexts is much greater than N, then *d = 2*
minimizes communication costs. You can read the paper to understand how *d*
affects communication costs. In general, the query consists of *d* BFV
ciphertexts and can index a database with *N^d* BFV plaintexts;  the response
consists of *F^(d-1)* ciphertexts, where *F* is the ciphertext
expansion factor. In the current implementation which uses recursive
modulo swithcing, *F* is around 4. We have not identified any setting where
*d > 2* is beneficial.


# Changelog

This implementation of SealPIR uses the latest version of SEAL, fixes several bugs,
and provides better serialization/deserialization of queries and responses,
and a more streamlined code base.

If you wish to use the **original** version of SealPIR which corresponds to the
numbers reported in the paper and which uses an older version  of SEAL, check
out [this](https://github.com/microsoft/SealPIR/tree/ccf86c50fd3291) branch in
the git repository.

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
