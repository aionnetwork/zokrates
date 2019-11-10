
<img src="http://www.redaktion.tu-berlin.de/fileadmin/fg308/icons/projekte/logos/ZoKrates_logo.svg" width="100%" height="180">

# ZoKrates (AVM)

ZoKrates is a toolbox for zkSNARKs. This fork augments the capabilities of ZoKrates by adding the following command to the command line interface (CLI) 
```
./zokrates export-avm-verifier [--proving-scheme <'G16'|'PGHR13'|'GM17'>] [--input <verifier path>] [--output <path>]
```
This command enables generation of SNARK verification contracts which can be deployed directly onto the Aion Virtual Machine (AVM). All other ZoKrates features (i.e. expressing SNARKs using the ZoKrates DSL) work as [documented](https://zokrates.github.io/). 

**Note:** Currently only the Groth 16 (G16) proving scheme is supported for AVM verifier export. Capabilities to export PGHR13 and GM17 will be added shortly. 

_This is a proof-of-concept implementation. It has not been tested for production._

## Getting Started

* Build zokrates using the `build.sh` or `build_release.sh` scripts (requires Rust to be [installed](https://rustup.rs/)).
* Express a SNARK using the ZoKrates DSL as usual (the [documentation](https://zokrates.github.io/introduction.html) is quite helpful). The built binary will be located in `target/release` or `target/debug` folder.
* When you're ready to generate a AVM contract containing the SNARK verification logic, simply run through the `compile` > `setup` > `compute-witness` > `generate-proof` steps using the built ZoKrates binary as usual. 
* Instead of calling `export-verifier` (which generates a Solidity contract), call `export-avm-verifier`, which generates a set of Java source files within a directory called `avm-verifier`. The entry-point to the AVM contract is called `Verifier.java`. 
* Deploy the contract files in the `avm-verifier` directory the usual way :)   



