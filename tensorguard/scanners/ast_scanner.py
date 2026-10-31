import ast
from typing import List
from tensorguard.rules import Vulnerability


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Vulnerability] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ("socket", "pty", "subprocess", "pynput"):
                self.findings.append(
                    Vulnerability(
                        file_path=self.file_path,
                        severity="MEDIUM",
                        rule_id="TG-002-SUSPICIOUS-IMPORT",
                        message=f"High-risk network/process library imported: `{alias.name}`",
                        evidence=f"Line {node.lineno}",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile"):
                self.findings.append(
                    Vulnerability(
                        file_path=self.file_path,
                        severity="HIGH",
                        rule_id="TG-003-DYNAMIC-EXEC",
                        message=f"Dynamic execution function `{node.func.id}()` called",
                        evidence=f"Line {node.lineno}",
                    )
                )
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            target = f"{node.func.value.id}.{node.func.attr}"
            if target in ("os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"):
                self.findings.append(
                    Vulnerability(
                        file_path=self.file_path,
                        severity="CRITICAL",
                        rule_id="TG-004-SHELL-EXEC",
                        message=f"Shell command invocation `{target}()` detected",
                        evidence=f"Line {node.lineno}",
                    )
                )
        self.generic_visit(node)


def scan_python_code(source_code: str, file_path: str) -> List[Vulnerability]:
    """Scan Python source code string in memory."""
    try:
        tree = ast.parse(source_code, filename=file_path)
        visitor = SecurityASTVisitor(file_path)
        visitor.visit(tree)
        return visitor.findings
    except Exception as e:
        return [
            Vulnerability(
                file_path=file_path,
                severity="MEDIUM",
                rule_id="TG-010-AST-PARSE-FAIL",
                message="Failed to parse Python source code AST",
                evidence=str(e),
            )
        ]


def scan_python_script(file_path: str) -> List[Vulnerability]:
    """Scan local Python file from disk."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return scan_python_code(content, file_path)
    except Exception as e:
        return [
            Vulnerability(
                file_path=file_path,
                severity="MEDIUM",
                rule_id="TG-010-AST-PARSE-FAIL",
                message="Failed to read file",
                evidence=str(e),
            )
        ]