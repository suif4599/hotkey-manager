"Hotkey Manager Module"

from typing import Callable, Optional

class HotkeyManagerInterface:
    "Hotkey Manager Interface"
    
    socket_path: str
    timeout_ms: int
    
    def __init__(self, socket_path: str, timeout_ms: int = 5000) -> None:
        "Initialize the HotkeyManagerInterface with socket_path and timeout_ms."

    def authenticate(self, password: str) -> None:
        "Authenticate with the hotkey manager using a password."

    def register_hotkey(self, hotkey: str, callback: Callable[[], None]) -> str:
        "Register a hotkey with a callback function."
    
    def delete_hotkey(self, hotkey: str) -> None:
        "Delete all callback functions for a hotkey."
    
    def delete_callback(self, callback: Callable[[], None]) -> None:
        "Delete the given callback function."

    def mainloop(self, keep_running: Optional[Callable[[], bool]] = None) -> None:
        "Start the main event loop to listen for hotkey events."
