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

#include <cstring>
#include <iostream>
#include <vector>

#include "time_service_client.h"
#include "utils.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace QueryTime {

// Forward declarations for command handlers
int CmdGetWallTime(int argc, char** argv);
int CmdGetBootTime(int argc, char** argv);
int CmdGetMonotonicTime(int argc, char** argv);
int CmdGetTimeZone(int argc, char** argv);
int CmdHelp(int argc, char** argv);

// Get static command table (lazy initialization)
const std::unordered_map<std::string, Command>& GetCommands()
{
    static const std::unordered_map<std::string, Command> kCommands = {
        {"get-wall-time", {"Get wall time (UTC time in milliseconds)", CmdGetWallTime}},
        {"get-boot-time", {"Get boot time (including sleep time)", CmdGetBootTime}},
        {"get-monotonic-time", {"Get monotonic time (excluding sleep time)", CmdGetMonotonicTime}},
        {"get-time-zone", {"Get current time zone", CmdGetTimeZone}},
        {"--help", {"Show help message", CmdHelp}},
    };
    return kCommands;
}

// Get TimeServiceClient instance
static sptr<TimeServiceClient> GetTimeClient()
{
    auto client = TimeServiceClient::GetInstance();
    if (client == nullptr) {
        CLI_ERROR("Failed to get TimeServiceClient instance");
    }
    return client;
}

// get-wall-time command
int CmdGetWallTime(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    auto client = GetTimeClient();
    if (client == nullptr) {
        return OutputError("ERR_CLIENT_INIT",
                           "Failed to initialize TimeServiceClient",
                           "Check if time_service system ability is running");
    }

    int64_t time = 0;
    int32_t ret = client->GetWallTimeMs(time);
    if (ret != 0) {
        return OutputError("ERR_GET_WALL_TIME",
                           "Failed to get wall time",
                           "Check system time service status and permissions");
    }

    json data;
    data["time"] = time;
    data["unit"] = "ms";
    return OutputSuccess(data);
}

// get-boot-time command
int CmdGetBootTime(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    auto client = GetTimeClient();
    if (client == nullptr) {
        return OutputError("ERR_CLIENT_INIT",
                           "Failed to initialize TimeServiceClient",
                           "Check if time_service system ability is running");
    }

    int64_t time = 0;
    int32_t ret = client->GetBootTimeMs(time);
    if (ret != 0) {
        return OutputError("ERR_GET_BOOT_TIME",
                           "Failed to get boot time",
                           "Check system time service status");
    }

    json data;
    data["time"] = time;
    data["unit"] = "ms";
    return OutputSuccess(data);
}

// get-monotonic-time command
int CmdGetMonotonicTime(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    auto client = GetTimeClient();
    if (client == nullptr) {
        return OutputError("ERR_CLIENT_INIT",
                           "Failed to initialize TimeServiceClient",
                           "Check if time_service system ability is running");
    }

    int64_t time = 0;
    int32_t ret = client->GetMonotonicTimeMs(time);
    if (ret != 0) {
        return OutputError("ERR_GET_MONOTONIC_TIME",
                           "Failed to get monotonic time",
                           "Check system time service status");
    }

    json data;
    data["time"] = time;
    data["unit"] = "ms";
    return OutputSuccess(data);
}

// get-time-zone command
int CmdGetTimeZone(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    auto client = GetTimeClient();
    if (client == nullptr) {
        return OutputError("ERR_CLIENT_INIT",
                           "Failed to initialize TimeServiceClient",
                           "Check if time_service system ability is running");
    }

    std::string timezone;
    int32_t ret = client->GetTimeZone(timezone);
    if (ret != 0) {
        return OutputError("ERR_GET_TIME_ZONE",
                           "Failed to get time zone",
                           "Check system time service status");
    }

    json data;
    data["timezone"] = timezone;
    return OutputSuccess(data);
}

// Parse target command from arguments
static std::string ParseTargetCommand(int argc, char** argv)
{
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            return argv[i];
        }
    }
    return "";
}

// Output help error response (text format)
static void OutputHelpError(const std::string& targetCmd)
{
    std::cout << "ERROR: Unknown command: " << targetCmd << std::endl;
    std::cout << "Suggestion: Use --help to see available commands" << std::endl;
}

// Print full help with all commands
static void PrintFullHelp()
{
    const auto& commands = GetCommands();

    std::cout << "Description: Query system time information" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: " << G_PROGRAM_NAME << " <command> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Available commands:" << std::endl;

    // Calculate max command name length for alignment
    constexpr size_t descriptionPadding = 2;
    size_t maxLen = 0;
    for (const auto& pair : commands) {
        if (pair.first != "--help" && pair.first.length() > maxLen) {
            maxLen = pair.first.length();
        }
    }

    for (const auto& pair : commands) {
        if (pair.first == "--help") {
            continue;
        }
        std::cout << "  " << pair.first;
        // Pad to align descriptions
        for (size_t i = pair.first.length(); i < maxLen + descriptionPadding; i++) {
            std::cout << " ";
        }
        std::cout << pair.second.description << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Run '" << G_PROGRAM_NAME << " <command> --help' for more information on a command." << std::endl;
}

// Print help for a single command
static int PrintCommandHelp(const std::string& targetCmd)
{
    const auto& commands = GetCommands();
    auto it = commands.find(targetCmd);
    if (it == commands.end()) {
        OutputHelpError(targetCmd);
        return 1;
    }

    std::cout << "Description: " << it->second.description << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: " << G_PROGRAM_NAME << " " << targetCmd << " [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << G_PROGRAM_NAME << " " << targetCmd << std::endl;

    return 0;
}

// help command - Output in text format to stdout
int CmdHelp(int argc, char** argv)
{
    std::string targetCmd = ParseTargetCommand(argc, argv);
    if (targetCmd.empty()) {
        PrintFullHelp();
        return 0;
    }
    return PrintCommandHelp(targetCmd);
}

} // namespace QueryTime
} // namespace OHOS
