# LUMOS: LLM-guided Stateful Fuzzing for Smart Contracts with Multi-Feedback and Dynamic Oracles

This repository provides the official implementation of the paper:

> **LUMOS: LLM-guided Stateful Fuzzing for Smart Contracts with Multi-Feedback and Dynamic Oracles**

LUMOS is a stateful smart contract fuzzing framework that integrates Large Language Models (LLMs), multi-feedback mechanisms, and dynamic semantic oracles to improve vulnerability detection in Ethereum smart contracts.

---

## 1. System Overview

LUMOS extends traditional stateful fuzzing by incorporating:

- LLM-guided seed generation  
- Stateful transaction sequence exploration  
- Multi-feedback coverage and execution monitoring  
- LLM-based dynamic vulnerability oracles  

The framework builds upon MuFuzz and enhances it with semantic reasoning and vulnerability-aware exploration.

---

## 2. System Requirements

LUMOS is designed to run on Linux systems.

**Recommended environment:**
- Ubuntu 18.04 (or later)

### Dependencies

- CMake ≥ 3.5.1  
- Python ≥ 3.9 (recommended: 3.9)  
- Go 1.15  
- LevelDB  
- Geth & Ethereum tools  
- solc 0.4.26  
- NumPy  

Additional Python dependencies are listed in:

```
tools/requirements.txt
```

---

## 3. Repository Structure

```
LUMOS
├── sFuzz/                # Core fuzzing engine (based on MuFuzz)
├── sample_rag/           # LLM-based RAG module
├── bran/                 # Abstract interpreter for path analysis
├── tools/                # Static analysis utilities
├── assets/               # Attacker contract templates
├── source_code/          # Original Solidity source files
├── clean_source_code/    # Normalized Solidity source files
├── contracts/            # Compiled contract artifacts
├── branch_msg/           # Intermediate path representations
├── logs/                 # Execution reports
├── fuzz/                 # Compiled fuzzing executable
├── llm_oracle.py         # LLM-based dynamic oracle
├── LUMOS_run.sh          # Main execution script
└── README.md
```

---

## 4. Google API Configuration

The RAG and LLM-based oracle components require a valid `GOOGLE_API_KEY`.

To make the API key accessible across both the root directory and the `sample_rag/` module, configure it as a global environment variable.

### Persistent Setup (Recommended)

For **bash** users:

```bash
echo 'export GOOGLE_API_KEY="your_api_key_here"' >> ~/.bashrc
source ~/.bashrc
```

For **zsh** users:

```bash
echo 'export GOOGLE_API_KEY="your_api_key_here"' >> ~/.zshrc
source ~/.zshrc
```

Verify configuration:

```bash
echo $GOOGLE_API_KEY
```

---

### Temporary Setup (Current Session Only)

```bash
export GOOGLE_API_KEY="your_api_key_here"
```

---

### Security Notice

Do **not** hardcode the API key inside:

- `config.yaml`
- `system_prompts.yaml`
- Any Python source file

Access it programmatically in Python:

```python
import os
api_key = os.getenv("GOOGLE_API_KEY")
```

---

## 5. Required Path Configuration (Important)

Two files contain hard-coded directory placeholders and must be updated before running LUMOS.

---

### 5.1 Update RAG Path in `Fuzzer.cpp`

In `Fuzzer.cpp`, locate:

```cpp
std::string jsonFilePath = "DIR-TO-RAG" + fullName + ".json";
```

Replace `"DIR-TO-RAG"` with the correct path to your `sample_rag/contracts` directory.

Recommended (if running from project root):

```cpp
std::string jsonFilePath = "./sample_rag/contracts/" + fullName + ".json";
```

---

### 5.2 Update Root Path in `LlamaRAG.py`

In:

```
sample_rag/RAG/rag_based_generation/LlamaRAG.py
```

Locate:

```python
if __name__ == "__main__":
    ROOT_DIR = "YOUR_ROOT_DIR/clean_source_code"
    run_hierarchical_pipeline(ROOT_DIR)
```

Replace `"YOUR_ROOT_DIR/clean_source_code"` with the correct path to your `clean_source_code` directory.

Recommended (if running from project root):

```python
ROOT_DIR = "./clean_source_code"
```

Ensure both paths match your local project structure before execution.

---

## 6. Complete Execution Pipeline

### Step 1 — System Initialization

```bash
./initial_.sh
```

This step installs required dependencies and prepares the environment.  
It may take significant time depending on your system and network speed.

---

### Step 2 — Workspace Preparation

```bash
./rename_src.sh
```

This prepares working directories under:

- `source_code/`
- `clean_source_code/`

---

### Step 3 — Execute LUMOS

```bash
./LUMOS_run.sh
```

The system will:

1. Compile contracts  
2. Initialize stateful fuzzing  
3. Invoke RAG-guided seed generation  
4. Execute multi-feedback fuzzing  
5. Trigger LLM-based dynamic oracle reasoning  
6. Generate execution logs in `logs/`  

---

## 7. Dataset

To support reproducibility and transparency, we publicly release all datasets used in our experiments.

The datasets include:

- Fully compilable Solidity smart contracts  
- Vulnerability-labeled samples  
- Evaluation contracts used in the paper  

**[Download](https://drive.google.com/drive/folders/1Qi6Lu4TYi6Lr8xJ8lbc6HOet_Tfn9rPz?usp=sharing)**

---

## 8. Reproducibility Notes

- Ensure `solc` version is strictly **0.4.26**.  
- Use Ubuntu 18.04 for consistent replication.  
- Fuzzing and LLM inference introduce stochastic behavior; multiple runs are recommended for stable evaluation.
