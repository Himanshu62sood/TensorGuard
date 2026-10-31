import numpy as np
from safetensors import safe_open
from scipy import stats
from typing import List
from tensorguard.rules import Vulnerability

class SafeTensorsScanner:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def scan(self) -> List[Vulnerability]:
        findings = []
        try:
            with safe_open(self.file_path, framework="numpy") as f:
                tensor_keys = list(f.keys())
                if not tensor_keys:
                    findings.append(
                        Vulnerability(
                            file_path=self.file_path,
                            severity="MEDIUM",
                            rule_id="TG-005-EMPTY-SAFE-TENSOR",
                            message="SafeTensors archive contains no active weight matrices",
                            evidence="Archive header is empty"
                        )
                    )

                # Sample up to 10 layers for performance efficiency
                for k in tensor_keys[:10]:
                    arr = f.get_tensor(k)
                    if not np.issubdtype(arr.dtype, np.floating):
                        continue

                    # 1. NaN or Inf check
                    if np.isnan(arr).any() or np.isinf(arr).any():
                        findings.append(
                            Vulnerability(
                                file_path=self.file_path,
                                severity="HIGH",
                                rule_id="TG-006-NAN-INF-WEIGHTS",
                                message=f"Corrupted or adversarial weights detected in layer `{k}`",
                                evidence="Contains NaN or Inf values"
                            )
                        )

                    # 2. Outlier / Backdoor signature check via kurtosis
                    flat = arr.flatten()
                    if flat.size > 1000:
                        sample = np.random.choice(flat, size=min(flat.size, 5000), replace=False)
                        kurt = float(stats.kurtosis(sample))
                        std = float(np.std(sample))
                        if kurt > 30.0 and std > 0.05:
                            findings.append(
                                Vulnerability(
                                    file_path=self.file_path,
                                    severity="LOW",
                                    rule_id="TG-007-WEIGHT-ANOMALY",
                                    message=f"Statistical anomaly in layer `{k}` (excess kurtosis {kurt:.2f})",
                                    evidence=f"Std: {std:.4f}, Kurtosis: {kurt:.2f}"
                                )
                            )
        except Exception as e:
            findings.append(
                Vulnerability(
                    file_path=self.file_path,
                    severity="HIGH",
                    rule_id="TG-008-SAFETENSORS-ERROR",
                    message="SafeTensors file structure could not be parsed",
                    evidence=str(e)
                )
            )
        return findings