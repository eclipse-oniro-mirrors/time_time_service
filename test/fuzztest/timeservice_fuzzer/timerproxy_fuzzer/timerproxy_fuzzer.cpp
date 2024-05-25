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

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_fuzz_utils.h"
#include "time_service_ipc_interface_code.h"
#include "timer_proxy.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;

bool FuzzTimerProxyTimer(const uint8_t *data, size_t size)
{
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm) {};
    int32_t uid = static_cast<int32_t>(*data);

    TimerProxy::GetInstance().ProxyTimer(uid, true, true, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, true, false, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, false, true, now, callback);
    TimerProxy::GetInstance().ProxyTimer(uid, false, false, now, callback);

    TimerProxy::GetInstance().PidProxyTimer(uid, true, true, now, callback);
    TimerProxy::GetInstance().PidProxyTimer(uid, true, false, now, callback);
    TimerProxy::GetInstance().PidProxyTimer(uid, false, true, now, callback);
    TimerProxy::GetInstance().PidProxyTimer(uid, false, false, now, callback);
    return true;
}

bool FuzzTimerAdjustTimer(const uint8_t *data, size_t size)
{
    auto interval = static_cast<uint32_t>(*data);
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (AdjustTimerCallback adjustTimer) {};
    TimerProxy::GetInstance().AdjustTimer(true, interval, now, callback);
    TimerProxy::GetInstance().AdjustTimer(false, interval, now, callback);
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
    auto now = std::chrono::steady_clock::now();
    auto callback = [] (std::shared_ptr<TimerInfo> &alarm) {};
    TimerProxy::GetInstance().ResetAllProxy(now, callback);
    return true;
}

bool FuzzTimerEraseTimer(const uint8_t *data, size_t size)
{
    auto id = static_cast<uint64_t>(*data);
    auto uid = static_cast<uint32_t>(*data);
    auto pid = static_cast<int>(*data);
    TimerProxy::GetInstance().EraseTimerFromProxyUidMap(id, uid);
    TimerProxy::GetInstance().EraseTimerFromProxyPidMap(id, pid);
    return true;
}

bool FuzzTimerRemoveTimerMap(const uint8_t *data, size_t size)
{
    auto id = static_cast<int64_t>(*data);
    TimerProxy::GetInstance().RemoveUidTimerMap(id);
    TimerProxy::GetInstance().RemovePidTimerMap(id);
    return true;
}

bool FuzzTimerIsProxy(const uint8_t *data, size_t size)
{
    auto id = static_cast<int32_t>(*data);
    TimerProxy::GetInstance().IsUidProxy(id);
    TimerProxy::GetInstance().IsPidProxy(id);
    return true;
}

bool FuzzTimerDelayTime(const uint8_t *data, size_t size)
{
    auto fd = static_cast<int>(*data);
    auto delay = static_cast<int64_t>(*data);
    TimerProxy::GetInstance().SetProxyDelayTime(fd, delay);
    TimerProxy::GetInstance().GetProxyDelayTime();
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
    OHOS::FuzzTimerDelayTime(data, size);
    return 0;
}