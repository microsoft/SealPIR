# SealPIR: A computational PIR library that achieves low communication costs and high performance.

SealPIR is a research library and should not be used in production systems. 
SealPIR allows a client to download an element from a database stored by a server without
revealing which element was downloaded. SealPIR was introduced at 
the Symposium on Security and Privacy (Oakland) in 2018. You can find
a copy of the paper [here](https://eprint.iacr.org/2017/1142.pdf).

# Compiling SEAL

SealPIR depends on [Microsoft SEAL version 3.2.0](https://github.com/microsoft/SEAL/tree/3.2.0).
Install SEAL before compiling SealPIR.

# Compiling SealPIR

Once Microsoft SEAL 3.2.0 is installed, to build SealPIR simply run:

	cmake .
	make
	
This should produce a binary file ``bin/sealpir``.

# Using SealPIR

Take a look at the example in main.cpp for how to use SealPIR. 
Note: the parameter "d" stands for recursion levels, and for the current configuration, the 
server-to-client reply has size (pow(10, d-1) * 32) KB. Therefore we recommend using d <= 3.  

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
