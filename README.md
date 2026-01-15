# hotkey-manager

`hotkey-manager` is a Linux daemon that captures hardware keyboard events, exposes them over an authenticated encrypted local IPC channel, and provides C++ and Python tooling to register callbacks for custom shortcuts.

## Features

- System daemon built on libevdev for low-level keyboard access (root required)
- Authenticated IPC over Unix domain sockets with libsodium-based public key exchange and Argon2 password hashes
- C++ shared library (`libhotkey-manager-client.so`) and Python ABI3 extension (`hotkey_manager.abi3.so`)
- Packaged as a systemd service with optional wheel generation during the build

## Requirements

- Linux with `systemd` and access to `/dev/input/event*`
- Build tooling: `cmake` >= 3.15, a C++17 compiler, `make`, `pkg-config`
- Libraries: `libevdev-dev`, `libsodium-dev`
- Utilities: `gzip`
- Optional (Python bindings): `python` >= 3.2, `pip`, `virtualenv`

Debian/Ubuntu example:

```bash
sudo apt install build-essential cmake pkg-config libevdev-dev libsodium-dev python3 python3-dev python3-venv gzip bash-completion
```

## Build

```bash
git clone https://github.com/suif4599/hotkey-manager.git
cd hotkey-manager
cmake -S . -B build -DBUILD_PYTHON_MODULE=ON
cmake --build build
```

Key build options:

- `-DBUILD_PYTHON_MODULE=ON` to build the Python wheel
- `-DPYTHON_EXECUTABLE=""` to specify the python executable to build the module, empty for auto
- `-DENABLE_DAEMON=OFF` to build without the systemd unit
- `-DSTART_DAEMON=OFF` to prevent the installer from immediately starting the service
- `-DGRAB_DEVICE=ON` to exclusively register a hotkey combination
- `-DALLOW_DUMP=OFF` to leave `PR_SET_DUMPABLE` default for client

`build/` will contain:

- `hotkey-manager-daemon`: daemon executable
- `hotkey-manager-daemon.service`: generated systemd unit file
- `libhotkey-manager-client.so`: shared library for C++ consumers
- `hotkey_manager-*-py3-none-*.whl`: Python wheel artifact

## Install

```bash
sudo cmake --install build
pip install build/hotkey_manager-*-py3-none-*.whl
```

The install target places the daemon in `/usr/local/bin`, installs headers and the shared library under `/usr/local/include` and `/usr/local/lib`, and copies the systemd unit to `/etc/systemd/system/` (enabling and optionally starting it according to the CMake options).

## Configuration

- Configuration lives at `/usr/local/etc/hotkey-manager-config.json`
- First launch creates a minimal config:

```json
{
	"deviceFile": "auto",
	"socketName": "hotkey-manager-ipc",
	"passwordHash": "$argon2id$...",
	"keyBinding": ""
}
```

- `deviceFile`: set to a specific `/dev/input/eventX` if auto-detection fails
- `socketName`: AF_UNIX abstract socket name exposed to clients (default `hotkey-manager-ipc`)
- `passwordHash`: Argon2 hash used for client authentication
- `keyBinding`: optional comma-separated key remaps in the form `FROM->TO`. Names must match `hotkey-manager-daemon keynames` output (without the `KEY_` prefix). Whitespace is ignored. Each source key may appear at most once and cannot map to itself. Example: `DELETE->F12, F12->DELETE, SYSRQ->F11, F11->SYSRQ`.

## Run the Daemon

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hotkey-manager-daemon.service
```

The daemon must run as root to read keyboard events. Logs will be written to syslog.

Usage:
| Command | Description |
| :---: | :---: |
| hotkey-manager-daemon | Start the daemon (Require ROOT) |
| hotkey-manager-daemon hash <password> | Generate password hash for given password |
| hotkey-manager-daemon keynames | List all available key names |
| hotkey-manager-daemon set <field> <value> | Modify the config file (Require ROOT). Fields: `deviceFile`, `socketName`, `passwordHash`, `keyBinding`. |
| hotkey-manager-daemon reset | Reset the config file to default values (Require ROOT). |

For example, use `sudo hotkey-manager-daemon set passwordHash $(hotkey-manager-daemon hash <password>)` to change password

## Client Libraries

### C++

Link against `libhotkey-manager-client.so` and include `hotkey_manager/interface.h`:

```cpp
#include "hotkey_manager/interface.h"

hotkey_manager::HotkeyInterface iface{"hotkey-manager-ipc"};
iface.authenticate("your-password");
iface.registerHotkey("LEFTCTRL+LEFTSHIFT+A", [] {
	// custom handler
});
iface.mainloop();
```

`mainloop` blocks and dispatches registered callbacks while handling keep-alives automatically.

- Hotkey shortcut grammer: [here]()
- Full API reference: [here]()

### Python

After installing the wheel:

```python
from hotkey_manager import HotkeyManagerInterface

manager = HotkeyManagerInterface("hotkey-manager-ipc")
manager.authenticate("your-password")

def on_hotkey():
	print("shortcut triggered")

manager.register_hotkey("Double(ESC)", on_hotkey)
manager.mainloop()
```

See `demo/client.py` for a more complete example, including cleanup helpers.

## Demos

- `demo/client.cpp`: minimal C++ console client (build with `cmake -S demo -B demo/build && cmake --build demo/build`)
- `demo/client.py`: Python walkthrough demonstrating registration and cleanup workflows

## Uninstall

```bash
sudo cmake --build build --target uninstall
pip uninstall hotkey-manager
```

## Hotkey Shortcut Grammar

### Syntax

```
Shortcut     := Combination | ModifierCall
Combination  := Key { "+" Key }
ModifierCall := Modifier "(" Shortcut [", " DurationMs] ")"
Modifier     := "None" | "Double" | "Hold"
DurationMs   := <integer literal in milliseconds>
Key          := name from `hotkey-manager-daemon keynames`
```

- Whitespace is ignored, so `CTRL+A`, `CTRL + A`, and `CTRL +  A` are equivalent.
- `+` requires every key in the combination to be held at the same time.
- Modifiers can wrap any shortcut (including nested modifiers) to change how activation is detected.
- Durations are optional; omitting them falls back to the 500 ms defaults used in the daemon.

### Keynames

- Run `hotkey-manager-daemon keynames` to list every available key symbol discovered via libevdev.
- Names are uppercase and follow libevdev conventions (for example `A`, `LEFTCTRL`, `F5`, `ESC`).
- Use the names verbatim—identifiers are case-sensitive and must match the output from the command above.

### Modifiers

- `None(...)`: Groups nested shortcuts without changing behaviour. There's no need to use it.
- `Double(...)`: Fires when the wrapped shortcut is pressed twice in succession. The optional duration sets the maximum gap (in milliseconds) between the release of the first press and the start of the second press. Default: 500 ms.
- `Hold(...)`: Fires when the wrapped shortcut has been held continuously for at least the specified duration (default 500 ms). Releasing the keys resets the hold timer.

### Examples

- `LEFTCTRL + LEFTSHIFT + A` - classic multi-modifier chord.
- `Double(ESC)` - double-tap Escape within the default 500 ms window.
- `Double(ESC, 300)` - double-tap Escape with a tighter 300 ms window.
- `Hold(LEFTALT, 1200)` - trigger after holding Left Alt for 1.2 seconds.
- `Hold(LEFTCTRL + C, 800)` - require both keys to stay pressed for 800 ms before activating.

## License

`hotkey-manager` is released under the GNU General Public License version 3 as published by the Free Software Foundation. See [LICENSE](./LICENSE) for details.
