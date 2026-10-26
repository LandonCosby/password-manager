#include <iostream>

#include "cli.h"
#include "crypto.h"
#include "terminal.h"

int main(int argc, char** argv) {
    if (!pm::init_crypto()) {
        std::cerr << "error: failed to initialize crypto library\n";
        return 1;
    }
    pm::ConsoleTerminal terminal;
    return pm::run_cli(pm::command_line_args(argc, argv), terminal);
}
