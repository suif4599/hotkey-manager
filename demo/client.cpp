#include <atomic>
#include <chrono>
#include <iostream>

#include "hotkey_manager/interface.h"

using namespace hotkey_manager;

int main() {
    try {
        // Establish the IPC session. The second argument keeps the default 5 second timeout
        HotkeyInterface hotkeyInterface;
        std::cout << "Connected to hotkey-manager daemon." << std::endl;

        // Authenticate once before attempting to register any shortcuts
        hotkeyInterface.authenticate("123456");
        std::cout << "Authentication succeeded." << std::endl;

        // The daemon can normalize shortcut descriptions; we display the normalized form to the user
        const std::string rawPrimaryHotkey = "LEFTCTRL+Double(A,1000)";
        const std::string normalizedPrimaryHotkey = hotkeyInterface.formatHotkey(rawPrimaryHotkey);
        std::cout << "Normalized form: " << normalizedPrimaryHotkey << std::endl;

        // Register the primary demo shortcut and use the returned string (formated) for later operations
        const std::string registeredPrimaryHotkey = hotkeyInterface.registerHotkey(
            rawPrimaryHotkey,
            []() {
                std::cout << "[demo] Primary double-tap A hotkey triggered." << std::endl;
            }
        );

        // Register an auxiliary callback that we will remove via deleteCallback to showcase the API
        const std::string callbackIdAux = "demo_aux";
        hotkeyInterface.registerHotkey(
            "LEFTALT + B",
            []() {
                std::cout << "[demo] Auxiliary LEFTALT + B hotkey triggered." << std::endl;
            },
            callbackIdAux
        );

        // Register a temporary hotkey and immediately remove it with formated hotkey string
        const std::string temporaryHotkey = hotkeyInterface.registerHotkey(
            "Double(C)",
            []() {
                std::cout << "[demo] Temporary hotkey triggered (unexpected)." << std::endl;
            }
        );
        hotkeyInterface.deleteHotkey(temporaryHotkey);
        std::cout << "Removed temporary hotkey: " << temporaryHotkey << std::endl;

        // Remove the auxiliary callback by its function identifier while keeping other callbacks intact
        hotkeyInterface.deleteCallback(callbackIdAux);
        std::cout << "Removed callback with id: " << callbackIdAux << std::endl;

        // Inspect the registered callbacks to verify the current state
        std::cout << "Currently registered callbacks:" << std::endl;
        for (const auto& [hotkey, callbacks] : hotkeyInterface.getCallbacks()) {
            std::cout << "  " << hotkey << " -> " << callbacks.size() << " callback(s)" << std::endl;
        }

        // The exit callback toggles a flag that the mainloop watchdog reads
        std::atomic<bool> keepRunning {true};
        hotkeyInterface.registerHotkey(
            "Double(ESC)",
            [&keepRunning]() {
                std::cout << "[demo] Exit hotkey triggered, stopping mainloop." << std::endl;
                keepRunning.store(false);
            },
            "demo_exit"
        );

        // Mainloop will check the keepRunning callback to determine whether to continue
        const auto startTime = std::chrono::steady_clock::now();
        const auto maxDemoDuration = std::chrono::seconds(60);
        hotkeyInterface.mainloop([&]() {
            if (!keepRunning.load()) {
                return false;
            }
            if (std::chrono::steady_clock::now() - startTime >= maxDemoDuration) {
                std::cout << "[demo] Auto-stopping mainloop after 30 seconds." << std::endl;
                return false;
            }
            return true;
        });

        std::cout << "Mainloop exited. Cleaning up." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[Error]: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}