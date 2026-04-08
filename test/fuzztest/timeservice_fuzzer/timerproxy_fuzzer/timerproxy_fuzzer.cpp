/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "timerproxy_fuzzer.h"
#include "timer_call_back.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_fuzz_utils.h"
#include "timer_proxy.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;
constexpr int MAX_NUM = 20;
constexpr int MAX_LENGTH = 64;

std::unordered_set<std::string> convertToUnorderedSetString(FuzzedDataProvider &provider)
{
    std::unordered_set<std::string> nameArr;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        std::string name = provider.ConsumeRandomLengthString(MAX_LENGTH);
        nameArr.insert(name);
    }
    return nameArr;
}

std::unordered_map<std::string, uint32_t> convertToUnorderedMap(FuzzedDataProvider &provider)
{
    std::unordered_map<std::string, uint32_t> policyMap;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        std::string name = provider.ConsumeRandomLengthString(MAX_LENGTH);
        int num = provider.ConsumeIntegral<int>();
        policyMap.insert({name, num});
    }
    return policyMap;
}

bool FuzzTimerProxyTimer(FuzzedDataProvider &provider)
{
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm, bool needRetrigger) {};
    int uid = provider.ConsumeIntegral<uint32_t>();
    int pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().ProxyTimer(uid, pid, true, true, now, callback);
    uid = provider.ConsumeIntegral<uint32_t>();
    pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().ProxyTimer(uid, pid, true, false, now, callback);
    uid = provider.ConsumeIntegral<uint32_t>();
    pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().ProxyTimer(uid, pid, false, true, now, callback);
    uid = provider.ConsumeIntegral<uint32_t>();
    pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().ProxyTimer(uid, pid, false, false, now, callback);
    return true;
}

bool FuzzTimerAdjustTimer(FuzzedDataProvider &provider)
{
    uint32_t interval = provider.ConsumeIntegral<uint32_t>();
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (AdjustTimerCallback adjustTimer) {};
    TimerProxy::GetInstance().AdjustTimer(true, interval, now, 0, callback);
    interval = provider.ConsumeIntegral<uint32_t>();
    TimerProxy::GetInstance().AdjustTimer(false, interval, now, 0, callback);
    return true;
}

bool FuzzTimerSetTimerExemption(FuzzedDataProvider &provider)
{
    std::unordered_set<std::string> nameArr = convertToUnorderedSetString(provider);
    TimerProxy::GetInstance().SetTimerExemption(nameArr, false);
    TimerProxy::GetInstance().SetTimerExemption(nameArr, true);
    return true;
}

bool FuzzTimerSetAdjustPolicy(FuzzedDataProvider &provider)
{
    std::unordered_map<std::string, uint32_t> policyMap = convertToUnorderedMap(provider);
    TimerProxy::GetInstance().SetAdjustPolicy(policyMap);
    return true;
}

bool FuzzTimerResetProxy(FuzzedDataProvider &provider)
{
    uint64_t offset = provider.ConsumeIntegral<uint64_t>();
    auto now = std::chrono::steady_clock::now() + std::chrono::nanoseconds(offset);
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm, bool needRetrigger) {};
    TimerProxy::GetInstance().ResetAllProxy(now, callback);
    return true;
}

bool FuzzTimerEraseTimer(FuzzedDataProvider &provider)
{
    uint64_t id = provider.ConsumeIntegral<uint64_t>();
    uint32_t uid = provider.ConsumeIntegral<uint32_t>();
    int pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(id, uid, pid);
    return true;
}

bool FuzzTimerRemoveTimerMap(FuzzedDataProvider &provider)
{
    int64_t id = provider.ConsumeIntegral<int64_t>();
    TimerProxy::GetInstance().RemoveUidTimerMap(id);
    return true;
}

bool FuzzTimerIsProxy(FuzzedDataProvider &provider)
{
    int uid = provider.ConsumeIntegral<int>();
    int pid = provider.ConsumeIntegral<int>();
    TimerProxy::GetInstance().IsProxy(uid, pid);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimerProxyTimer(provider);
    OHOS::FuzzTimerAdjustTimer(provider);
    OHOS::FuzzTimerSetTimerExemption(provider);
    OHOS::FuzzTimerResetProxy(provider);
    OHOS::FuzzTimerEraseTimer(provider);
    OHOS::FuzzTimerRemoveTimerMap(provider);
    OHOS::FuzzTimerIsProxy(provider);
    OHOS::FuzzTimerSetAdjustPolicy(provider);
    return 0;
}