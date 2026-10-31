import os
import pickle
import pytest
import numpy as np

from tensorguard.scanners.ast_scanner import scan_python_script
from tensorguard.scanners.pickle_scanner import PickleScanner
from tensorguard.scanners.tensor_scanner import SafeTensorsScanner
from tensorguard.remediation.sanitizer import sanitize_pickle_to_safetensors


@pytest.fixture
def benign_pickle(tmp_path):
    file_path = tmp_path / "benign.pkl"
    weights = {
        "fc.weight": np.ones((4, 4), dtype=np.float32),
        "fc.bias": np.zeros((4,), dtype=np.float32),
    }
    with open(file_path, "wb") as f:
        pickle.dump(weights, f)
    return str(file_path)


@pytest.fixture
def malicious_pickle(tmp_path):
    file_path = tmp_path / "malicious.pkl"
    # Construct an arbitrary command execution payload using byte injection
    payload = b"cos\nsystem\n(S'whoami'\ntR."
    with open(file_path, "wb") as f:
        f.write(payload)
    return str(file_path)


@pytest.fixture
def malicious_script(tmp_path):
    file_path = tmp_path / "modeling_unsafe.py"
    file_path.write_text("import subprocess\nsubprocess.Popen(['bash', '-i'])")
    return str(file_path)


def test_ast_scanner_detects_shell_exec(malicious_script):
    findings = scan_python_script(malicious_script)
    rule_ids = [f.rule_id for f in findings]
    assert "TG-002-SUSPICIOUS-IMPORT" in rule_ids
    assert "TG-004-SHELL-EXEC" in rule_ids


def test_pickle_scanner_flags_command_injection(malicious_pickle):
    scanner = PickleScanner(malicious_pickle)
    findings = scanner.scan()
    assert len(findings) > 0
    assert any(f.rule_id == "TG-001-PICKLE-RCE" for f in findings)


def test_sanitizer_blocks_malicious_deserialization(malicious_pickle, tmp_path):
    out_file = str(tmp_path / "cleaned.safetensors")
    with pytest.raises(RuntimeError) as exc_info:
        sanitize_pickle_to_safetensors(malicious_pickle, out_file)
    assert "Malicious payload intercepted" in str(exc_info.value)


def test_sanitizer_converts_benign_checkpoint(benign_pickle, tmp_path):
    out_file = str(tmp_path / "cleaned.safetensors")
    success = sanitize_pickle_to_safetensors(benign_pickle, out_file)
    assert success is True
    assert os.path.exists(out_file)

    # Verify the generated safetensors file passes our tensor scanner
    scanner = SafeTensorsScanner(out_file)
    findings = scanner.scan()
    assert len(findings) == 0