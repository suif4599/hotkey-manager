#include "daemon/manager.h"
#include "config.h"
#include <stdexcept>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>

using namespace hotkey_manager;

int main(int argc, char* argv[]) {
    if (argc != 1) {
        std::string command = argv[1];
        if (command == "hash" && argc == 3) {
            std::string password = argv[2];
            std::string hash = Encryptor::hashPassword(password);
            std::cout << hash << std::endl;
            return 0;
        }
        if (command == "keynames" && argc == 2) {
            auto keys = KeyMapper::getInstance().availableKeys();
            if (isatty(fileno(stdout))) {
                // To terminal
                struct winsize w;
                int width = 80;
                if (ioctl(fileno(stdout), TIOCGWINSZ, &w) == 0) {
                    width = w.ws_col;
                }
                int maxKeyLength = 0;
                for (const auto& key : keys) {
                    if (key.length() > static_cast<size_t>(maxKeyLength))
                        maxKeyLength = key.length();
                }
                int num = width / (maxKeyLength + 2);
                for (size_t i = 0; i < keys.size(); ++i) {
                    std::cout << keys[i];
                    int padding = maxKeyLength - keys[i].length() + 2;
                    for (int p = 0; p < padding; ++p)
                        std::cout << " ";
                    if ((i + 1) % num == 0 || i == keys.size() - 1)
                        std::cout << "\n";
                }
            } else {
                // To pipe/file
                for (size_t i = 0; i < keys.size(); ++i) {
                    std::cout << keys[i];
                    if (i != keys.size() - 1) {
                        std::cout << "\n";
                    }
                }
            }
            return 0;
        }
        if (command == "-h" || command == "--help") {
            std::cout << "hotkey-manager-daemon: Daemon for hotkey-manager\n"
                      << "Usage:\n"
                      << "    hotkey-manager-daemon                    Start the daemon\n"
                      << "    hotkey-manager-daemon hash <password>    Generate password hash for given password\n\n"
                      << "    hotkey-manager-daemon keynames           List all available key names\n\n"
                      << "Config file is located at `" << CONFIG_FILE_PATH << "`\n"
                      << "Example config file content:\n"
                      << "{\n"
                      << "    \"deviceFile\": \"/dev/input/event0\",\n"
                      << "    \"socketPath\": \"/tmp/hotkey-manager.sock\",\n"
                      << "    \"passwordHash\": \"$argon2id$v=19$m=65536,t=2,p=1$gVhSWbbAsC+mm2QfArc/xw$5fdVpc61mjx0xkbrMVi9YCXhIcl29h3fHvZkYO4TsIU\"\n"
                      << "}\n";
        }
        std::cerr << "Usage: hotkey-manager-daemon [hash <password>]" << std::endl;
        return 1;
    }

    openlog("hotkey-manager", LOG_PID | LOG_CONS, LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_NOTICE));
    if (geteuid() != 0) {
        syslog(LOG_ERR, "This program must be run as root.");
        closelog();
        return 1;
    }
    try {
        HotkeyManager::getInstance(CONFIG_FILE_PATH).mainloop();
    } catch (const std::exception& e) {
        syslog(LOG_ERR, "Fatal error: %s", e.what());
        closelog();
        return 1;
    }
    return 0;
}