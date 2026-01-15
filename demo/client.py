"""Comprehensive demo for the Python bindings of hotkey-manager."""

import os
import signal
import threading
import time

from hotkey_manager import HotkeyManagerInterface


def schedule_sigint(delay_seconds: int) -> None:
    """Send SIGINT after delay_seconds so the demo stops even without hotkeys."""

    def _worker() -> None:
        time.sleep(delay_seconds)
        print(f"[demo] No exit hotkey within {delay_seconds} seconds, stopping mainloop.")
        os.kill(os.getpid(), signal.SIGINT)

    threading.Thread(target=_worker, daemon=True).start()


def main() -> None:
    manager = HotkeyManagerInterface()
    print("Connected to hotkey-manager daemon.")

    manager.authenticate("pass")
    print("Authentication succeeded.")

    # Register the primary hotkey that will stay active for the entire demo
    def on_primary() -> None:
        print("[demo] LEFTCTRL+LEFTSHIFT+A triggered.")

    manager.register_hotkey("LEFTCTRL+LEFTSHIFT+A", on_primary)
    print("Registered primary demo hotkey.")

    # Demonstrate that delete_hotkey removes every callback bound to a shortcut
    def on_temporary() -> None:
        print("[demo] Temporary hotkey triggered (unexpected).")

    manager.register_hotkey("Double(C)", on_temporary)
    manager.delete_hotkey("Double(C)")
    print("Registered and removed temporary hotkey Double(C).")

    # Showcase delete_callback by registering and then removing a specific callable
    def on_removable() -> None:
        print("[demo] Removable callback triggered (unexpected).")

    manager.register_hotkey("LEFTALT + B", on_removable)
    manager.delete_callback(on_removable)
    print("Registered and removed callback via delete_callback.")

    # The exit callback terminates the mainloop by raising KeyboardInterrupt with SIGINT
    def on_exit() -> None:
        print("[demo] Exit hotkey triggered, sending SIGINT to stop mainloop.")
        os.kill(os.getpid(), signal.SIGINT)

    manager.register_hotkey("Double(ESC)", on_exit)
    print("Registered exit hotkey Double(ESC). Use it or wait for timeout.")

    schedule_sigint(30)

    try:
        manager.mainloop()
    except KeyboardInterrupt:
        print("[demo] Mainloop stopped.")


if __name__ == "__main__":
    main()
