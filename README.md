# TensorGuard 🛡️
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
git clone [https://github.com/](https://github.com/)<your-username>/TensorGuard.git
cd TensorGuard
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -e .