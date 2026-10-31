import os
import pickle
import numpy as np
from safetensors.numpy import save_file

os.makedirs("test_models/clean", exist_ok=True)
os.makedirs("test_models/malicious", exist_ok=True)

# 1. Clean SafeTensors model
tensors_clean = {"weights.layer1": np.random.randn(64, 64).astype(np.float32)}
save_file(tensors_clean, "test_models/clean/model.safetensors")

# 2. Malicious Pickle payload (Simulated RCE)
class MaliciousExploit:
    def __reduce__(self):
        import os
        return (os.system, ("calc.exe",))

with open("test_models/malicious/pytorch_model.bin", "wb") as f:
    pickle.dump(MaliciousExploit(), f)

# 3. Malicious Python modeling script
with open("test_models/malicious/modeling_exploit.py", "w", encoding="utf-8") as f:
    f.write("import subprocess\nsubprocess.Popen(['powershell', '-c', 'Get-Process'])\n")

print("✓ Successfully generated test artifacts in `test_models/clean` and `test_models/malicious`")