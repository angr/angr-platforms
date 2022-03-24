# Tricore Lifter

The lifter includes the [tricore instruction set v1.3 & v1.3.1](https://www.infineon.com/dgdl/tc_v131_instructionset_v138.pdf?fileId=db3a304412b407950112b409b6dd0352).

### Usage
1. Build & Install angr-platforms 
    - python3 setup.py build
    - sudo python3 setup.py install
2. Import tricore lifter in your module:
    - from angr_platforms.tricore import *

## Tests
The test module makes sure that the angr functionalities are working on tricore architecture. The test binary files are generated from source code of angr challenges by compiling them with tricore toolchain.

### Usage
- python3 tests/test_tricore.py
