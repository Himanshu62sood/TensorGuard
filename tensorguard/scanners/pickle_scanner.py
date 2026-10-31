import pickletools
from typing import List
from tensorguard.rules import Vulnerability

# High-risk execution sinks, shell spawners, dynamic imports, and network hooks
DANGEROUS_IMPORTS = {
    "os": {"system", "popen", "kill", "spawn", "execl"},
    "posix": {"system"},
    "nt": {"system"},
    "subprocess": {"Popen", "run", "call", "check_output"},
    "builtins": {"exec", "eval", "compile", "__import__", "open"},
    "socket": {"socket", "connect"},
    "urllib.request": {"urlopen"},
    "pip": {"main", "_internal"},
    "pty": {"spawn"},
}


class PickleScanner:
    def __init__(self, file_path: str = ""):
        self.file_path = file_path

    def scan(self) -> List[Vulnerability]:
        """Scan local pickle file from disk."""
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
            return self.scan_bytes(data, self.file_path, is_partial=False)
        except Exception as e:
            return [
                Vulnerability(
                    file_path=self.file_path,
                    severity="HIGH",
                    rule_id="TG-009-PARSE-FAIL",
                    message="Malformed pickle header or unreadable file",
                    evidence=str(e),
                )
            ]

    def scan_bytes(self, raw_data: bytes, file_name: str, is_partial: bool = True) -> List[Vulnerability]:
        """Scan raw in-memory bytes (local or remote HTTP range chunks)."""
        findings = []
        if not raw_data:
            return findings

        # Skip ZIP archives when scanning raw pickle opcodes
        if raw_data.startswith(b"PK\x03\x04"):
            return findings

        stack = []
        try:
            for opcode, arg, pos in pickletools.genops(raw_data):
                if opcode.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINSTRING", "SHORT_BINSTRING"):
                    stack.append(str(arg))

                elif opcode.name == "GLOBAL" and arg:
                    module_name, func_name = arg.split(" ", 1) if " " in arg else (arg, "")
                    if self._is_dangerous(module_name, func_name):
                        findings.append(self._create_vuln(file_name, module_name, func_name, opcode.name, pos))

                elif opcode.name == "STACK_GLOBAL":
                    if len(stack) >= 2:
                        func_name = stack.pop()
                        module_name = stack.pop()
                        if self._is_dangerous(module_name, func_name):
                            findings.append(self._create_vuln(file_name, module_name, func_name, opcode.name, pos))

        except Exception as e:
            # If scanning a partial HTTP Range chunk, EOF or opcode truncation is expected
            if not is_partial:
                findings.append(
                    Vulnerability(
                        file_path=file_name,
                        severity="HIGH",
                        rule_id="TG-009-PARSE-FAIL",
                        message="Malformed pickle header or corrupted stream",
                        evidence=str(e),
                    )
                )
        return findings

    def _is_dangerous(self, module_name: str, func_name: str) -> bool:
        if module_name in DANGEROUS_IMPORTS:
            restricted = DANGEROUS_IMPORTS[module_name]
            return not restricted or func_name in restricted
        return False

    def _create_vuln(self, file_path: str, module_name: str, func_name: str, opcode_name: str, pos: int) -> Vulnerability:
        return Vulnerability(
            file_path=file_path,
            severity="CRITICAL",
            rule_id="TG-001-PICKLE-RCE",
            message=f"Dangerous execution trigger `{module_name}.{func_name}` found in serialized stream",
            evidence=f"Opcode {opcode_name} at byte offset {pos}",
        )