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


#include "timerproxy_state_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "timer_info.h"
#include "timer_proxy.h"

namespace OHOS {
namespace {
constexpr int FUZZ_FD = -1;
constexpr int32_t CALLBACK_ERROR = -1;
constexpr size_t MAX_TIMER_COUNT = 3;
constexpr uint64_t MAX_TIMER_ID = 4096;
constexpr uint64_t HOURS_PER_DAY = 24ULL;
constexpr uint64_t MINUTES_PER_HOUR = 60ULL;
constexpr uint64_t SECONDS_PER_MINUTE = 60ULL;
constexpr uint64_t MILLISECONDS_PER_SECOND = 1000ULL;
constexpr uint64_t MAX_TRIGGER_MS = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE *
    MILLISECONDS_PER_SECOND;
constexpr int64_t MIN_WINDOW_MS = -1;
constexpr int64_t MAX_WINDOW_MS = MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
constexpr uint32_t MAX_TIMER_FLAGS = 0x7F;
constexpr int MAX_TIMER_TYPE = 3;
constexpr uint32_t MAX_POLICY_VALUE = 2;
constexpr uint32_t MAX_ADJUST_SECONDS = 3600;

using TimerInfoPtr = std::shared_ptr<MiscServices::TimerInfo>;
using TimerInfoList = std::vector<TimerInfoPtr>;
using TimerExemptionSet = std::unordered_set<std::string>;

std::string ConsumeFixedBundle(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> bundles = {
        "time_service", "settings", "TimerProxyState", "proxy.bundle"
    };
    return bundles[provider.ConsumeIntegralInRange<size_t>(0, bundles.size() - 1)];
}

TimerInfoPtr CreateProxyTimer(FuzzedDataProvider &provider, uint64_t id)
{
    auto callback = [](const uint64_t timerId) -> int32_t {
        return timerId == 0 ? CALLBACK_ERROR : 0;
    };
    int type = provider.ConsumeIntegralInRange<int>(0, MAX_TIMER_TYPE);
    uint64_t triggerTime = provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TRIGGER_MS);
    int64_t windowLength = provider.ConsumeBool() ? 0 :
        provider.ConsumeIntegralInRange<int64_t>(MIN_WINDOW_MS, MAX_WINDOW_MS);
    uint64_t interval = provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TRIGGER_MS);
    uint32_t flags = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TIMER_FLAGS);
    int uid = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(MAX_TIMER_ID));
    int pid = provider.ConsumeIntegralInRange<int>(0, static_cast<int>(MAX_TIMER_ID));
    return MiscServices::TimerInfo::CreateTimerInfo("proxy.timer", id, type, triggerTime, windowLength, interval,
        flags, provider.ConsumeBool(), callback, nullptr, uid, pid, ConsumeFixedBundle(provider));
}

std::chrono::steady_clock::time_point ConsumeTimePoint(FuzzedDataProvider &provider)
{
    return std::chrono::steady_clock::time_point(std::chrono::milliseconds(
        provider.ConsumeIntegralInRange<int64_t>(0, static_cast<int64_t>(MAX_TRIGGER_MS))));
}

TimerExemptionSet BuildExemptionSet(const TimerInfoList &timers)
{
    std::unordered_set<std::string> names = { "time_service", "settings", "TimerProxyState" };
    for (const auto &timer : timers) {
        if (timer != nullptr) {
            names.insert(timer->bundleName);
            names.insert(timer->bundleName + "|" + timer->name);
        }
    }
    return names;
}

std::unordered_map<std::string, uint32_t> BuildPolicyMap(FuzzedDataProvider &provider,
    const TimerInfoList &timers)
{
    std::unordered_map<std::string, uint32_t> policyMap;
    policyMap["time_service"] = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_POLICY_VALUE);
    policyMap["settings"] = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_POLICY_VALUE);
    for (const auto &timer : timers) {
        if (timer != nullptr) {
            policyMap[timer->bundleName] = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_POLICY_VALUE);
        }
    }
    return policyMap;
}

void InsertAlarmCallback(std::shared_ptr<MiscServices::TimerInfo> &alarm, bool needRetrigger)
{
    if (alarm == nullptr) {
        return;
    }
    if (needRetrigger) {
        (void)alarm->RestoreProxyTimer();
    }
}

void ExerciseAdjustTimers(TimerInfoList &timers, MiscServices::AdjustTimerCallback adjustTimer)
{
    for (auto &timer : timers) {
        (void)adjustTimer(timer);
    }
    TimerInfoPtr nullTimer;
    (void)adjustTimer(nullTimer);
}

void RecordTimerMaps(MiscServices::TimerProxy &timerProxy, FuzzedDataProvider &provider, TimerInfoList &timers)
{
    size_t timerCount = provider.ConsumeIntegralInRange<size_t>(1, MAX_TIMER_COUNT);
    timers.reserve(timerCount);
    for (size_t index = 0; index < timerCount; ++index) {
        auto timer = CreateProxyTimer(provider, provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_ID));
        if (timer == nullptr) {
            continue;
        }
        timers.emplace_back(timer);
        timerProxy.RecordUidTimerMap(timer, false);
        timerProxy.RecordUidTimerMap(timer, true);
        timerProxy.RecordProxyTimerMap(timer, provider.ConsumeBool());
        (void)timerProxy.CallbackAlarmIfNeed(timer);
        (void)timerProxy.CountUidTimerMapByUid(timer->uid);
        (void)timerProxy.IsTimerExemption(timer);
        (void)timerProxy.IsProxy(timer->uid, timer->pid);
        (void)timerProxy.IsProxyLocked(timer->uid, timer->pid);
    }
    TimerInfoPtr nullTimer;
    (void)timerProxy.CallbackAlarmIfNeed(nullTimer);
}

void ExerciseProxyTimers(MiscServices::TimerProxy &timerProxy, FuzzedDataProvider &provider,
    TimerInfoList &timers, const std::chrono::steady_clock::time_point &now)
{
    for (auto &timer : timers) {
        (void)timerProxy.ProxyTimer(timer->uid, provider.ConsumeBool() ? timer->pid : 0,
            true, provider.ConsumeBool(), now, InsertAlarmCallback);
        (void)timerProxy.ProxyTimer(timer->uid, provider.ConsumeBool() ? timer->pid : 0,
            false, provider.ConsumeBool(), now, InsertAlarmCallback);
    }
}

void ExerciseAdjustPolicy(MiscServices::TimerProxy &timerProxy, FuzzedDataProvider &provider,
    TimerInfoList &timers, const std::chrono::steady_clock::time_point &now)
{
    auto updateTimerDeliveries = [&timers](MiscServices::AdjustTimerCallback adjustTimer) {
        ExerciseAdjustTimers(timers, adjustTimer);
    };
    (void)timerProxy.AdjustTimer(true, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS),
        now, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS), updateTimerDeliveries);
    (void)timerProxy.AdjustTimer(false, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS),
        now, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS), updateTimerDeliveries);
    auto getProxyDelay = &MiscServices::TimerProxy::GetProxyDelayTime;
    (void)(timerProxy.*getProxyDelay)();
}

void ShowProxyState(MiscServices::TimerProxy &timerProxy, FuzzedDataProvider &provider)
{
#ifdef HIDUMPER_ENABLE
    (void)timerProxy.ShowProxyTimerInfo(FUZZ_FD, provider.ConsumeIntegral<int64_t>());
    (void)timerProxy.ShowUidTimerMapInfo(FUZZ_FD, provider.ConsumeIntegral<int64_t>());
    auto showProxyDelay = &MiscServices::TimerProxy::ShowProxyDelayTime;
    (void)(timerProxy.*showProxyDelay)(FUZZ_FD);
    timerProxy.ShowAdjustTimerInfo(FUZZ_FD);
#else
    auto bytes = provider.ConsumeRemainingBytes<uint8_t>();
    (void)bytes;
#endif
}

void ClearTimerMaps(MiscServices::TimerProxy &timerProxy, TimerInfoList &timers,
    const TimerExemptionSet &exemptionSet, const std::chrono::steady_clock::time_point &now)
{
    for (auto &timer : timers) {
        timerProxy.EraseTimerFromProxyTimerMap(timer->id, timer->uid, timer->pid);
        timerProxy.RemoveUidTimerMap(timer);
        timerProxy.RemoveUidTimerMap(timer->id);
    }
    (void)timerProxy.ResetAllProxy(now, InsertAlarmCallback);
    (void)timerProxy.SetTimerExemption(exemptionSet, false);
}
} // namespace

void RunTimerproxyStateFuzzer(FuzzedDataProvider &provider)
{
    auto &timerProxy = MiscServices::TimerProxy::GetInstance();
    TimerInfoList timers;
    RecordTimerMaps(timerProxy, provider, timers);

    auto exemptionSet = BuildExemptionSet(timers);
    (void)timerProxy.SetTimerExemption(exemptionSet, true);
    timerProxy.SetAdjustPolicy(BuildPolicyMap(provider, timers));

    auto now = ConsumeTimePoint(provider);
    ExerciseProxyTimers(timerProxy, provider, timers, now);
    ExerciseAdjustPolicy(timerProxy, provider, timers, now);
    ShowProxyState(timerProxy, provider);
    ClearTimerMaps(timerProxy, timers, exemptionSet, now);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimerproxyStateFuzzer(provider);
    return 0;
}
