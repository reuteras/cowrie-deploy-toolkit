# Import dynamic filesystem to ensure monkey patching happens
try:
    from . import fs_dynamic  # noqa: F401
except ImportError:
    pass
