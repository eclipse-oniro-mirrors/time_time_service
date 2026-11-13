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

#include "timedumpcmd_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#ifdef HIDUMPER_ENABLE
#include "time_cmd_dispatcher.h"
#include "time_system_ability.h"
#endif

namespace OHOS {
namespace {
constexpr int FUZZ_FD = -1;
constexpr size_t MIN_COMMAND_COUNT = 1;
constexpr size_t MAX_COMMAND_COUNT = 3;
constexpr size_t MAX_TAIL_LENGTH = 32;

enum DumpCommandOpcode : uint8_t {
    DUMP_EMPTY = 0,
    DUMP_HELP,
    DUMP_TIME,
    DUMP_TIMER_ALL,
    DUMP_TIMER_INFO,
    DUMP_TIMER_START,
    DUMP_IDLE_ALL,
    DUMP_PROXY_TIMER,
    DUMP_UID_TIMER,
    DUMP_PROXY_DELAY_TIME,
    DUMP_ADJUST_ALL,
    DUMP_TIMER_INVALID_TAIL,
    DUMP_TIMER_MISSING_ID,
    DUMP_INVALID,
};

constexpr uint8_t MIN_COMMAND_INDEX = DUMP_EMPTY;
constexpr uint8_t MAX_COMMAND_INDEX = DUMP_INVALID;

using CommandArgs = std::vector<std::string>;

std::string ConsumeTail(FuzzedDataProvider &provider)
{
    if (provider.ConsumeBool()) {
        return std::to_string(provider.ConsumeIntegral<uint64_t>());
    }
    return provider.ConsumeRandomLengthString(MAX_TAIL_LENGTH);
}

CommandArgs BuildDumpArgs(FuzzedDataProvider &provider)
{
    uint8_t opcode = provider.ConsumeIntegralInRange<uint8_t>(MIN_COMMAND_INDEX, MAX_COMMAND_INDEX);
    std::string id = std::to_string(provider.ConsumeIntegral<uint64_t>());
    switch (opcode) {
        case DUMP_EMPTY:
            return {};
        case DUMP_HELP:
            return { "-h" };
        case DUMP_TIME:
            return { "-time" };
        case DUMP_TIMER_ALL:
            return { "-timer", "-a" };
        case DUMP_TIMER_INFO:
            return { "-timer", "-i", id };
        case DUMP_TIMER_START:
            return { "-timer", "-s", id };
        case DUMP_IDLE_ALL:
            return { "-idle", "-a" };
        case DUMP_PROXY_TIMER:
            return { "-ProxyTimer", "-l" };
        case DUMP_UID_TIMER:
            return { "-UidTimer", "-l" };
        case DUMP_PROXY_DELAY_TIME:
            return { "-ProxyDelayTime", "-l" };
        case DUMP_ADJUST_ALL:
            return { "-adjust", "-a" };
        case DUMP_TIMER_INVALID_TAIL:
            return { "-timer", ConsumeTail(provider) };
        case DUMP_TIMER_MISSING_ID:
            return { "-timer", "-i" };
        default:
            return { ConsumeTail(provider), ConsumeTail(provider), ConsumeTail(provider) };
    }
}

std::vector<std::u16string> ToU16Args(const CommandArgs &args)
{
    std::vector<std::u16string> result;
    result.reserve(args.size());
    for (const auto &arg : args) {
        std::u16string converted;
        converted.reserve(arg.size());
        for (unsigned char ch : arg) {
            converted.push_back(static_cast<char16_t>(ch));
        }
        result.emplace_back(std::move(converted));
    }
    return result;
}

#ifdef HIDUMPER_ENABLE
void EnsureDumpCommandsRegistered()
{
    static std::once_flag initFlag;
    std::call_once(initFlag, []() {
        MiscServices::TimeSystemAbility::GetInstance()->InitDumpCmd();
    });
}
#endif
} // namespace

void RunTimedumpcmdFuzzer(FuzzedDataProvider &provider)
{
#ifdef HIDUMPER_ENABLE
    EnsureDumpCommandsRegistered();
    size_t commandCount = provider.ConsumeIntegralInRange<size_t>(MIN_COMMAND_COUNT, MAX_COMMAND_COUNT);
    for (size_t index = 0; index < commandCount; ++index) {
        auto args = BuildDumpArgs(provider);
        (void)MiscServices::TimeCmdDispatcher::GetInstance().Dispatch(FUZZ_FD, args);
        auto u16Args = ToU16Args(args);
        (void)MiscServices::TimeSystemAbility::GetInstance()->Dump(FUZZ_FD, u16Args);
    }
#else
    auto bytes = provider.ConsumeRemainingBytes<uint8_t>();
    (void)bytes;
#endif
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimedumpcmdFuzzer(provider);
    return 0;
}
