"Python bindings for the hotkey-manager daemon."

from typing import Callable, Optional

class HotkeyManagerInterface:
    "High-level client for interacting with the hotkey-manager daemon."
    
    socket_path: str
    timeout_ms: int
    
    def __init__(self, socket_path: str, timeout_ms: int = 5000) -> None:
        "Create a new interface bound to socket_path and optional timeout_ms."

    def authenticate(self, password: str) -> None:
        "Authenticate this process with the daemon using the configured password."

    def register_hotkey(self, hotkey: str, callback: Callable[[], None]) -> str:
        "Register a hotkey expression and associate a zero-argument callback."
    
    def delete_hotkey(self, hotkey: str) -> None:
        "Remove all callbacks registered for the given hotkey expression."
    
    def delete_callback(self, callback: Callable[[], None]) -> None:
        "Remove a previously registered callback object from every hotkey."

    def mainloop(self, keep_running: Optional[Callable[[], bool]] = None) -> None:
        "Enter the event loop to dispatch hotkey callbacks; optional keep_running controls exit."
