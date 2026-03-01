# LUMOS-Fuzzing-smart-contract
A code implementation of paper, entitled: "LUMOS: LLM-guided Stateful Fuzzing for Smart Contracts with Multi-Feedback and Dynamic Oracles"

## Requirements

LUMOS is executed on Linux (ideally Ubuntu 18.04).

Dependencies: 

* [CMake](https://cmake.org/download/): >=[3.5.1](sFuzz/CMakeLists.txt#L5)
* [Python](https://www.python.org/downloads/): >=3.9（ideally 3.9）
* Go: 1.15
* leveldb
* [Geth & Tools](https://geth.ethereum.org/downloads/)
* solc: 0.4.26
* numpy


## Architecture

```shell
$(LUMOS)
├── sFuzz
│   ├── fuzzer
│   ├── libfuzzer
│   ├── liboracle
│   └── ...
├── sample_rag
│   ├── RAG
│   ├── data
│   ├── config.yaml
│   ├── system_prompts.yaml
├── bran
│   └── ...
├── tools
│   ├── requirements.txt
│   └── ...
├── assets
│   ├── ReentrancyAttacker_model.sol
│   ├── ReentrancyAttacker.sol
│   └── ...
├── source_code
│   └── ...
├── clean_source_code
│   └── ...
├── contracts
│   └── ...
├── branch_msg
│   └── ...
├── logs
│   └── ...
├── fuzz
├── initial_.sh
├── rename_src.sh
├── run.sh
├── llm_oracle.py
├── run_multi_order.sh
├── json_to_csv.py
├── LUMOS_run.sh
└── README.md
```
* `sFuzz`: The basic fuzzing module of MuFuzz
* `bran`: The abstract interpreter for path analysis
* `tools`: The static analysis tools for extracting vulnerability-specific patterns
  * `requirements.txt`：Required python dependencies
* `assets`:
  * `ReentrancyAttacker_model.sol`: The template for constructing an attacker contract
  * `ReentrancyAttacker.sol`: The attacker contract generated based on the template
* `source_code`: Store the source code (`.sol`) of a contract
* `clean_source_code`: Store the clean source code (`.sol`) of a contract
* `contracts/example1`: Store the compiled results of a contract
* `branch_msg`: Store the intermediate representations of a contract
* `logs`: Store the execution report during fuzzing
* `fuzz`: The complied executable fuzzer file (if you want to re-compile a fuzz file, you can refer to the following *complete execution*)

## Complete Execution

- Initialization and Install system dependencies (This step will consume a lot of time.)

```bash
./initial_.sh
```

- Make workspace for the contract in directory `source_code` and `clean_source_code`

```bash
./rename_src.sh
```

- Run LUMOS

```bash
./LUMOS_run.sh
```

### Dataset
We publicly release all two datasets used in our experiments to support reproducibility. [Download](https://drive.google.com/drive/folders/1Qi6Lu4TYi6Lr8xJ8lbc6HOet_Tfn9rPz?usp=sharing)
