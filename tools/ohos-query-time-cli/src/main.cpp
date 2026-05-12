/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "commands.h"
#include "utils.h"

#include <cstring>
#include <iostream>

namespace OHOS {
namespace QueryTime {

// Global program name
const char* G_PROGRAM_NAME = "";

} // namespace QueryTime
} // namespace OHOS

using namespace OHOS::QueryTime;

// Constants for argument count checks
constexpr int ARG_COUNT_HELP_ONLY = 2;         // argc == 2: program + --help
constexpr int ARG_COUNT_SUBCOMMAND_HELP = 3;   // argc == 3: program + cmd + --help
constexpr int MIN_REQUIRED_ARGS = 2;           // argc < 2: missing command
constexpr int CMD_NAME_SKIP_COUNT = 2;         // skip program name + command name
constexpr int SUBCMD_ARGV_INDEX = 2;           // argv[2]: subcommand for <cli> <cmd> --help

int main(int argc, char* argv[])
{
    G_PROGRAM_NAME = argv[0];

    // Check for missing command
    if (argc < MIN_REQUIRED_ARGS) {
        return CmdHelp(argc, argv);
    }

    // Initialize command table (only once)
    // Commands are statically initialized, no runtime initialization needed

    // Handle <cli-name> --help
    if (argc == ARG_COUNT_HELP_ONLY && std::strcmp(argv[1], "--help") == 0) {
        return CmdHelp(argc, argv);
    }

    std::string cmdName = argv[1];

    // Handle <cli-name> <subcommand> --help
    if (argc == ARG_COUNT_SUBCOMMAND_HELP && std::strcmp(argv[SUBCMD_ARGV_INDEX], "--help") == 0) {
        return CmdHelp(argc, argv);
    }

    const auto& commands = GetCommands();
    auto it = commands.find(cmdName);
    if (it == commands.end()) {
        return OutputError("ERR_UNKNOWN_COMMAND",
            "Unknown command: " + cmdName,
            "Use --help to see available commands");
    }

    // Invoke command handler with remaining parameters
    return it->second.handler(argc - CMD_NAME_SKIP_COUNT, argv + CMD_NAME_SKIP_COUNT);
}
