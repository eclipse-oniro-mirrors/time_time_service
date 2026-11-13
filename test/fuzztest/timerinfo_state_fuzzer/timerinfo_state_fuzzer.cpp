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

#include "timerinfo_state_fuzzer.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#define private public // NOLINT
#include "timer_info.h"
#undef private

namespace OHOS {
namespace {
constexpr size_t MAX_STRING_LENGTH = 48;
constexpr uint64_t MAX_TIMER_ID = 4096;
constexpr uint64_t DAYS_PER_MONTH = 30ULL;
constexpr uint64_t HOURS_PER_DAY = 24ULL;
constexpr uint64_t HALF_DAY_HOURS = 12ULL;
constexpr uint64_t MINUTES_PER_HOUR = 60ULL;
constexpr uint64_t SECONDS_PER_MINUTE = 60ULL;
constexpr uint64_t MILLISECONDS_PER_SECOND = 1000ULL;
constexpr uint64_t NANOSECONDS_PER_MILLISECOND = 1000000ULL;
constexpr uint64_t MAX_TRIGGER_MS = DAYS_PER_MONTH * HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE *
    MILLISECONDS_PER_SECOND;
constexpr uint64_t MAX_INTERVAL_MS = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
constexpr int64_t MAX_WINDOW_MS = HALF_DAY_HOURS * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
constexpr int64_t MIN_WINDOW_MS = -1;
constexpr int64_t MAX_PROXY_DELAY_MS = MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
constexpr int64_t MAX_OFFSET_NS = MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND *
    NANOSECONDS_PER_MILLISECOND;
constexpr uint32_t MAX_TIMER_FLAGS = 0x7F;
constexpr uint32_t MIN_ADJUST_SECONDS = 1;
constexpr uint32_t MAX_ADJUST_SECONDS = 3600;
constexpr uint32_t MAX_ADJUST_POLICY = 2;
constexpr int MIN_TIMER_STATE = -4;
constexpr int MAX_TIMER_STATE = 8;
constexpr int32_t INVALID_TIMER_TYPE = -1;
constexpr int32_t OUT_OF_RANGE_TIMER_TYPE = 4;
constexpr int32_t MAX_UINT8_TIMER_TYPE = 255;
constexpr size_t TIMER_TYPE_SAMPLE_COUNT = 7;
constexpr size_t MIN_OPERATION_COUNT = 1;
constexpr size_t MAX_OPERATION_COUNT = 3;

enum TimerStateOpcode : uint8_t {
    TIMER_CALCULATE_ELAPSED = 0,
    TIMER_UPDATE_WHEN_ELAPSED,
    TIMER_PROXY,
    TIMER_RESTORE_PROXY,
    TIMER_ADJUST,
    TIMER_RESTORE_ADJUST,
    TIMER_CONVERT_ADJUST_POLICY,
    TIMER_RESTORE_GENERIC,
};

constexpr uint8_t MIN_OPERATION_INDEX = TIMER_CALCULATE_ELAPSED;
constexpr uint8_t MAX_OPERATION_INDEX = TIMER_RESTORE_GENERIC;

std::string ConsumeBoundedString(FuzzedDataProvider &provider, const std::vector<std::string> &values)
{
    if (provider.ConsumeBool()) {
        return values[provider.ConsumeIntegralInRange<size_t>(0, values.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
}

std::string ConsumeBundleName(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> bundleNames = {
        "time_service", "settings", "TimerInfoState", "bundle.timer", "bundle.timer|state", ""
    };
    return ConsumeBoundedString(provider, bundleNames);
}

int32_t ConsumeTimerType(FuzzedDataProvider &provider)
{
    static const std::array<int32_t, TIMER_TYPE_SAMPLE_COUNT> timerTypes = {
        MiscServices::ITimerManager::RTC_WAKEUP,
        MiscServices::ITimerManager::RTC,
        MiscServices::ITimerManager::ELAPSED_REALTIME_WAKEUP,
        MiscServices::ITimerManager::ELAPSED_REALTIME,
        INVALID_TIMER_TYPE,
        OUT_OF_RANGE_TIMER_TYPE,
        MAX_UINT8_TIMER_TYPE,
    };
    return timerTypes[provider.ConsumeIntegralInRange<size_t>(0, timerTypes.size() - 1)];
}

std::shared_ptr<MiscServices::TimerInfo> CreateTimerInfo(FuzzedDataProvider &provider, uint64_t id)
{
    auto callback = [](const uint64_t timerId) -> int32_t {
        return timerId == 0 ? -1 : 0;
    };
    std::string name = ConsumeBoundedString(provider, { "state.timer", "time_service", "settings", "" });
    int32_t type = ConsumeTimerType(provider);
    uint64_t triggerTime = provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TRIGGER_MS);
    int64_t windowLength = provider.ConsumeIntegralInRange<int64_t>(MIN_WINDOW_MS, MAX_WINDOW_MS);
    uint64_t interval = provider.ConsumeIntegralInRange<uint64_t>(0, MAX_INTERVAL_MS);
    uint32_t flags = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TIMER_FLAGS);
    int uid = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(MAX_TIMER_ID));
    int pid = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(MAX_TIMER_ID));
    return MiscServices::TimerInfo::CreateTimerInfo(name, id, type, triggerTime, windowLength, interval, flags,
        provider.ConsumeBool(), callback, nullptr, uid, pid, ConsumeBundleName(provider));
}

std::chrono::steady_clock::time_point ConsumeTimePoint(FuzzedDataProvider &provider)
{
    auto millis = provider.ConsumeIntegralInRange<int64_t>(0, static_cast<int64_t>(MAX_TRIGGER_MS));
    return std::chrono::steady_clock::time_point(std::chrono::milliseconds(millis));
}

void ExerciseTimerState(std::shared_ptr<MiscServices::TimerInfo> &timer, FuzzedDataProvider &provider)
{
    if (timer == nullptr) {
        return;
    }
    auto now = ConsumeTimePoint(provider);
    uint8_t opcode = provider.ConsumeIntegralInRange<uint8_t>(MIN_OPERATION_INDEX, MAX_OPERATION_INDEX);
    switch (opcode) {
        case TIMER_CALCULATE_ELAPSED:
            timer->CalculateOriWhenElapsed();
            timer->CalculateWhenElapsed(now);
            break;
        case TIMER_UPDATE_WHEN_ELAPSED:
            (void)timer->UpdateWhenElapsedFromNow(now,
                std::chrono::nanoseconds(provider.ConsumeIntegralInRange<int64_t>(0, MAX_OFFSET_NS)));
            break;
        case TIMER_PROXY:
            (void)timer->ProxyTimer(now,
                std::chrono::milliseconds(provider.ConsumeIntegralInRange<int64_t>(0, MAX_PROXY_DELAY_MS)));
            break;
        case TIMER_RESTORE_PROXY:
            (void)timer->RestoreProxyTimer();
            break;
        case TIMER_ADJUST:
            (void)timer->AdjustTimer(now, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS),
                provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS),
                provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_POLICY));
            break;
        case TIMER_RESTORE_ADJUST:
            (void)timer->RestoreAdjustTimer();
            break;
        case TIMER_CONVERT_ADJUST_POLICY: {
            (void)timer->ChangeStatusToAdjust();
            auto interval = provider.ConsumeIntegralInRange<uint32_t>(MIN_ADJUST_SECONDS, MAX_ADJUST_SECONDS);
            (void)timer->ConvertAdjustPolicy(interval,
                provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_POLICY));
            break;
        }
        default:
            timer->state = provider.ConsumeIntegralInRange<int>(MIN_TIMER_STATE, MAX_TIMER_STATE);
            (void)timer->RestoreTimer();
            break;
    }
}
} // namespace

void RunTimerinfoStateFuzzer(FuzzedDataProvider &provider)
{
    uint64_t id = provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_ID);
    auto timer = CreateTimerInfo(provider, id);
    auto duplicate = CreateTimerInfo(provider, provider.ConsumeBool() ? id : id + MIN_OPERATION_COUNT);
    if (timer == nullptr || duplicate == nullptr) {
        return;
    }

    (void)(*timer == *duplicate);
    (void)timer->Matches(ConsumeBundleName(provider));
    (void)MiscServices::TimerInfo::ConvertToElapsed(std::chrono::milliseconds(
        provider.ConsumeIntegralInRange<int64_t>(0, static_cast<int64_t>(MAX_TRIGGER_MS))), ConsumeTimerType(provider));
    auto maxTrigger = &MiscServices::TimerInfo::MaxTriggerTime;
    (void)maxTrigger(ConsumeTimePoint(provider), ConsumeTimePoint(provider),
        std::chrono::milliseconds(provider.ConsumeIntegralInRange<int64_t>(0, MAX_PROXY_DELAY_MS)));

    size_t operationCount = provider.ConsumeIntegralInRange<size_t>(MIN_OPERATION_COUNT, MAX_OPERATION_COUNT);
    for (size_t index = 0; index < operationCount; ++index) {
        ExerciseTimerState(timer, provider);
    }
    (void)timer->RestoreProxyTimer();
    (void)timer->RestoreAdjustTimer();
    timer.reset();
    duplicate.reset();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimerinfoStateFuzzer(provider);
    return 0;
}
