/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "timecmdparser_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "time_cmd_dispatcher.h"
#include "time_cmd_parse.h"

namespace OHOS {
namespace {
constexpr int FUZZ_FD = -1;
constexpr size_t MAX_TOKEN_LENGTH = 32;
constexpr size_t MAX_FORMAT_TOKEN_COUNT = 3;
constexpr size_t MIN_DISPATCH_COUNT = 1;
constexpr size_t MAX_DISPATCH_COUNT = 3;

enum CommandOpcode : uint8_t {
    COMMAND_EMPTY = 0,
    COMMAND_HELP,
    COMMAND_TIME,
    COMMAND_TIMER_ALL,
    COMMAND_TIMER_INFO,
    COMMAND_TIMER_START,
    COMMAND_IDLE_ALL,
    COMMAND_PROXY_TIMER,
    COMMAND_UID_TIMER,
    COMMAND_PROXY_DELAY_TIME,
    COMMAND_ADJUST_ALL,
    COMMAND_INVALID,
};

constexpr uint8_t MIN_COMMAND_INDEX = COMMAND_EMPTY;
constexpr uint8_t MAX_COMMAND_INDEX = COMMAND_INVALID;

using CommandArgs = std::vector<std::string>;

const std::vector<CommandArgs> &GetFixedFormats()
{
    static const std::vector<CommandArgs> formats = {
        { "-time" },
        { "-timer", "-a" },
        { "-timer", "-i", "[n]" },
        { "-timer", "-s", "[n]" },
        { "-idle", "-a" },
        { "-ProxyTimer", "-l" },
        { "-UidTimer", "-l" },
        { "-ProxyDelayTime", "-l" },
        { "-adjust", "-a" },
    };
    return formats;
}

std::string ConsumeToken(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> tokens = {
        "", "-h", "-time", "-timer", "-i", "-s", "-a", "-idle", "-ProxyTimer", "-UidTimer",
        "-ProxyDelayTime", "-adjust", "-l", "0", "1", "12345", "invalid",
    };
    if (provider.ConsumeBool()) {
        return tokens[provider.ConsumeIntegralInRange<size_t>(0, tokens.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_TOKEN_LENGTH);
}

CommandArgs BuildDispatchArgs(FuzzedDataProvider &provider)
{
    uint8_t opcode = provider.ConsumeIntegralInRange<uint8_t>(MIN_COMMAND_INDEX, MAX_COMMAND_INDEX);
    std::string timerId = std::to_string(provider.ConsumeIntegral<uint64_t>());
    switch (opcode) {
        case COMMAND_EMPTY:
            return {};
        case COMMAND_HELP:
            return { "-h" };
        case COMMAND_TIME:
            return { "-time" };
        case COMMAND_TIMER_ALL:
            return { "-timer", "-a" };
        case COMMAND_TIMER_INFO:
            return { "-timer", "-i", timerId };
        case COMMAND_TIMER_START:
            return { "-timer", "-s", timerId };
        case COMMAND_IDLE_ALL:
            return { "-idle", "-a" };
        case COMMAND_PROXY_TIMER:
            return { "-ProxyTimer", "-l" };
        case COMMAND_UID_TIMER:
            return { "-UidTimer", "-l" };
        case COMMAND_PROXY_DELAY_TIME:
            return { "-ProxyDelayTime", "-l" };
        case COMMAND_ADJUST_ALL:
            return { "-adjust", "-a" };
        default:
            return { ConsumeToken(provider), ConsumeToken(provider), timerId };
    }
}

CommandArgs BuildParserFormat(FuzzedDataProvider &provider)
{
    if (provider.ConsumeBool()) {
        const auto &formats = GetFixedFormats();
        return formats[provider.ConsumeIntegralInRange<size_t>(0, formats.size() - 1)];
    }

    CommandArgs format;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, MAX_FORMAT_TOKEN_COUNT);
    for (size_t index = 0; index < count; ++index) {
        format.emplace_back(ConsumeToken(provider));
    }
    return format;
}

void RegisterFixedCommands()
{
    static std::once_flag registerFlag;
    std::call_once(registerFlag, []() {
        auto action = [](int fd, const CommandArgs &input) {
            (void)fd;
            (void)input;
        };
        for (const auto &format : GetFixedFormats()) {
            auto command = std::make_shared<TimeCmdParse>(format, "fuzz command", action);
            MiscServices::TimeCmdDispatcher::GetInstance().RegisterCommand(command);
        }
    });
}
} // namespace

void RunTimecmdparserFuzzer(FuzzedDataProvider &provider)
{
    RegisterFixedCommands();

    auto action = [](int fd, const CommandArgs &input) {
        (void)fd;
        (void)input;
    };
    TimeCmdParse parser(BuildParserFormat(provider), provider.ConsumeRandomLengthString(MAX_TOKEN_LENGTH), action);
    (void)parser.ShowHelp();
    (void)parser.GetOption();
    (void)parser.GetFormat();
    parser.DoAction(FUZZ_FD, BuildDispatchArgs(provider));

    size_t dispatchCount = provider.ConsumeIntegralInRange<size_t>(MIN_DISPATCH_COUNT, MAX_DISPATCH_COUNT);
    for (size_t index = 0; index < dispatchCount; ++index) {
        auto args = BuildDispatchArgs(provider);
        (void)MiscServices::TimeCmdDispatcher::GetInstance().getCmdTitle(FUZZ_FD, args);
        (void)MiscServices::TimeCmdDispatcher::GetInstance().Dispatch(FUZZ_FD, args);
    }
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimecmdparserFuzzer(provider);
    return 0;
}
