import numpy as np

def convert_numpy_to_python_types(obj):
    """
    Recursively convert numpy types to native Python types.
    """
    if isinstance(obj, np.ndarray):
        return convert_numpy_to_python_types(obj.tolist())
    elif isinstance(obj, np.number):
        return float(obj) if isinstance(obj, np.floating) else int(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, dict):
        return {k: convert_numpy_to_python_types(v) for k, v in obj.items()}
    elif isinstance(obj, list) or isinstance(obj, tuple):
        return [convert_numpy_to_python_types(item) for item in obj]
    else:
        return obj
