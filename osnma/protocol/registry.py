# Simple registry for protocol adapters
# Add as osnma/protocol/registry.py

_registry = {}

def register(name: str, adapter_cls):
    _registry[name] = adapter_cls

def get(name: str):
    cls = _registry.get(name)
    if cls is None:
        raise KeyError(f'Protocol adapter "{name}" not registered')
    return cls
