# TensorGuard 🛡️
[![TensorGuard AI Supply Chain Gate](https://github.com/Himanshu62sood/TensorGuard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Himanshu62sood/TensorGuard/actions/workflows/security-scan.yml)
> **Lightweight AI Model Supply Chain & Serialization Security Scanner**

TensorGuard detects, isolates, and remediates arbitrary code execution (RCE) vectors in serialized AI models and repository scripts. It maps findings directly to **OWASP Top 10 for LLMs (LLM05: Supply Chain Vulnerabilities)**.

---

## ⚡ Core Capabilities

- **Zero-Trust Pickle Disassembly**: Disassembles opcode sequences via `pickletools` without importing or invoking pickled payloads. Intercepts `STACK_GLOBAL`, `GLOBAL`, and process hooks (`nt.system`, `posix.system`, `subprocess`, etc.).
- **Static Script AST Analysis**: Parses repository companion scripts (`modeling_*.py`, tokenizers) using Python's native `ast` engine to flag reverse shells, unauthorized socket connections, and system command executions.
- **SafeTensors Integrity & Header Verification**: Validates header byte allocations, JSON boundaries, and offset alignments in `.safetensors` files to protect against out-of-bounds reads and memory-mapping exploits.
- **Remote In-Memory Inspection (`scan-hf`)**: Streams model headers from remote Hugging Face repositories via chunked HTTP range queries, inspecting file signatures without cloning heavy checkpoints.
- **Restricted Remediation Engine (`sanitize`)**: Converts legacy, high-risk pickle checkpoints into secure, zero-exploit `.safetensors` using an isolated `RestrictedUnpickler` and NumPy.
- **Auditing & Executive Reporting**: Records every scan run in a persistent SQLite audit database and exports HTML compliance dashboards.

---

## 🚀 Installation

```bash
git clone https://github.com/Himanshu62sood/TensorGuard.git
cd TensorGuard
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On Linux/macOS:
source .venv/bin/activate

pip install -e .

💻 CLI Usage
1. Scan Local Artifacts
# Scan a directory or model file with a fail-safe threshold
tensorguard scan ./path-to-models --fail-on HIGH
2. Remote Hugging Face Scan
# Inspect a remote repo in-memory without downloading gigabytes of weights
tensorguard scan-hf prajjwal1/bert-tiny --fail-on HIGH
3. Sanitize Legacy Pickles
# Safely convert pickle checkpoints to SafeTensors
tensorguard sanitize weights.bin --output weights_clean.safetensors
4. Audit History & Compliance Report
# View past scan histories from SQLite
tensorguard history

# Export executive HTML report
tensorguard report -o audit_report.html
🏛️ Architecture Overview
┌────────────────────────────┐
                      │    TensorGuard CLI Entry   │
                      └─────────────┬──────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
  ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
  │   AST Scanner   │      │ Pickle Scanner  │      │ Tensor Scanner  │
  │ (Script Parser) │      │(Opcode Analyzer)│      │(SafeTensors Val)│
  └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    ▼
                      ┌────────────────────────────┐
                      │   Evaluation Gate & Rules  │
                      └─────────────┬──────────────┘
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
┌──────────────────────┐                         ┌──────────────────────┐
│ SQLite Audit Storage │                         │  Sanitizer Engine    │
│(tensorguard_audit.db)│                         │(Pickle -> Safetensor)│
└──────────┬───────────┘                         └──────────────────────┘
           ▼
┌──────────────────────┐
│ HTML Executive Report│
└──────────────────────┘
🔒 Security Model
TensorGuard enforces execution boundaries through:
1.Restricted Class Deserialization: Restricts unpickling strictly to mathematical array primitives (numpy.ndarray, standard structures) and drops unknown modules.

2.Pure Opcode Disassembly: Pickle validation uses state machines over disassembled bytecode tokens rather than calling pickle.load().

3.Chunked Stream Analysis: SafeTensors inspection only pulls the 8-byte metadata header and JSON manifest, mitigating Denial-of-Service (DoS) buffer allocation attacks.
📄 License
Distributed under the Apache-2.0 License.
---

### Push the Updated README to GitHub

Run these commands in PowerShell:

```powershell
git add README.md
git commit -m "docs: finalize README with live CI badge and accurate clone path"
git push origin main