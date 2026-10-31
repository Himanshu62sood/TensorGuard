import io
import pickle
from typing import Dict, Any
import numpy as np
from safetensors.numpy import save_file

# Whitelist safe numerical structures and reconstruction primitives
SAFE_MODULE_WHITELIST = {
    ("collections", "OrderedDict"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy", "ndarray"),
    ("numpy", "dtype"),
    ("_codecs", "encode"),
}


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that restricts objects strictly to safe data structures."""

    def find_class(self, module: str, name: str):
        # Allow safe primitives
        if (module, name) in SAFE_MODULE_WHITELIST or module.startswith("numpy"):
            return super().find_class(module, name)

        # Intercept any process/code execution or arbitrary hooks
        raise pickle.UnpicklingError(f"Security blocked non-whitelisted object: '{module}.{name}'")


def sanitize_pickle_to_safetensors(input_path: str, output_path: str) -> bool:
    """Safely extracts tensor arrays from a pickle file and serializes them into SafeTensors format."""
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    stream = io.BytesIO(file_bytes)
    unpickler = RestrictedUnpickler(stream)

    try:
        data = unpickler.load()
    except pickle.UnpicklingError as e:
        raise RuntimeError(f"Sanitization halted: Malicious payload intercepted! ({e})")
    except Exception as e:
        raise RuntimeError(f"Failed to parse model stream safely: {e}")

    if not isinstance(data, dict):
        raise ValueError("Invalid model format: Root serialized object must be a dictionary.")

    clean_tensors: Dict[str, np.ndarray] = {}
    for key, val in data.items():
        if isinstance(val, np.ndarray):
            clean_tensors[str(key)] = val
        elif hasattr(val, "numpy"):  # Handle tensor wrappers if present
            clean_tensors[str(key)] = val.numpy()

    if not clean_tensors:
        raise ValueError("No extractable numerical arrays found in the checkpoint.")

    save_file(clean_tensors, output_path)
    return True