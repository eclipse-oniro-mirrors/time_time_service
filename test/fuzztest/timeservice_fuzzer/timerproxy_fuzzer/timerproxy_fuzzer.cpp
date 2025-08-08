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

bool FuzzTimerProxyTimer(const uint8_t *data, size_t size)
{
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm, bool needRetrigger) {};
    FuzzedDataProvider fdp(data, size);
    int uid = fdp.ConsumeIntegral<uint32_t>();
    int pid = fdp.ConsumeIntegral<int>();

    TimerProxy::GetInstance().ProxyTimer(uid, pid, true, true, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, pid, true, false, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, pid, false, true, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, pid, false, false, now, callback);
    return true;
}

bool FuzzTimerAdjustTimer(const uint8_t *data, size_t size)
{
    auto interval = static_cast<uint32_t>(*data);
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (AdjustTimerCallback adjustTimer) {};
    TimerProxy::GetInstance().AdjustTimer(true, interval, now, 0, callback);
    TimerProxy::GetInstance().AdjustTimer(false, interval, now, 0, callback);
    return true;
}

bool FuzzTimerSetTimerExemption(const uint8_t *data, size_t size)
{
    std::string name(reinterpret_cast<const char *>(data), size);
    std::unordered_set<std::string> nameArr{name};
    TimerProxy::GetInstance().SetTimerExemption(nameArr, false);
    TimerProxy::GetInstance().SetTimerExemption(nameArr, true);
    return true;
}

bool FuzzTimerResetProxy(const uint8_t *data, size_t size)
{
    uint64_t offset = static_cast<uint64_t>(*data);
    auto now = std::chrono::steady_clock::now() + std::chrono::nanoseconds(offset);
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm, bool needRetrigger) {};
    TimerProxy::GetInstance().ResetAllProxy(now, callback);
    return true;
}

bool FuzzTimerEraseTimer(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint64_t id = fdp.ConsumeIntegral<uint64_t>();
    uint32_t uid = fdp.ConsumeIntegral<uint32_t>();
    int pid = fdp.ConsumeIntegral<int>();
    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(id, uid, pid);
    return true;
}

bool FuzzTimerRemoveTimerMap(const uint8_t *data, size_t size)
{
    auto id = static_cast<int64_t>(*data);
    TimerProxy::GetInstance().RemoveUidTimerMap(id);
    return true;
}

bool FuzzTimerIsProxy(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int uid = fdp.ConsumeIntegral<int>();
    int pid = fdp.ConsumeIntegral<int>();
    TimerProxy::GetInstance().IsProxy(uid, pid);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzTimerProxyTimer(data, size);
    OHOS::FuzzTimerAdjustTimer(data, size);
    OHOS::FuzzTimerSetTimerExemption(data, size);
    OHOS::FuzzTimerResetProxy(data, size);
    OHOS::FuzzTimerEraseTimer(data, size);
    OHOS::FuzzTimerRemoveTimerMap(data, size);
    OHOS::FuzzTimerIsProxy(data, size);
    return 0;
}