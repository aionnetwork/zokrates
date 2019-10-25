
<img src="http://www.redaktion.tu-berlin.de/fileadmin/fg308/icons/projekte/logos/ZoKrates_logo.svg" width="100%" height="180">

# ZoKrates (AVM)

ZoKrates is a toolbox for zkSNARKs. This fork (maintained by the Open Foundation) augments the capabilities of ZoKrates via the cli command `export-avm-verifier`, to enable one to generate SNARK verification contracts that can be deployed on the Aion Virtual Machine. The remaining features in ZoKrates (i.e. expressing programs using the ZoKrates DSL) work the usual way. 

**Note:** Currently only the Groth 16 proving scheme  is supported for AVM verifier export. Capabilities to export PGHR13 and GM17 will be added shortly. 

_This is a proof-of-concept implementation. It has not been tested for production._

## Getting Started

* Build zokrates using the `build.sh` script. (the 
* Zokrates will create a folder called verifier, in which will be all Java source files. The contract is called `Verifier.java`.
* Deploy on AVM the usual way :)   

## Writing SNARKS

You can write SNARKs

Have a look at the [documentation](https://zokrates.github.io/) for more information about using ZoKrates.  
A getting started tutorial can be found [here](https://zokrates.github.io/sha256example.html).

