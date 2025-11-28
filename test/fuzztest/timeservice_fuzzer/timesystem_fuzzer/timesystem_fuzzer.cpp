/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "itime_service.h"
#include "timesystem_fuzzer.h"
#include "time_system_ability.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

using namespace OHOS::MiscServices;

namespace OHOS {
const int MAX_NUM = 20;
const int MAX_LENGTH = 50;

std::vector<std::string> convertToVectorString(FuzzedDataProvider &provider)
{
    std::vector<std::string> result;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        std::string name = provider.ConsumeRandomLengthString(MAX_LENGTH);
        result.push_back(name);
    }
    return result;
}

std::vector<int> convertToVectorInt(FuzzedDataProvider &provider)
{
    std::vector<int> result;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        int value = provider.ConsumeIntegral<int>();
        result.push_back(value);
    }
    return result;
}

bool CreateTimerFuzzTest(FuzzedDataProvider &provider)
{
    std::string name(provider.ConsumeRandomLengthString());
    int type = provider.ConsumeIntegral<int>();
    bool repeat = provider.ConsumeBool();
    bool disposable = provider.ConsumeBool();
    bool autoRestore = provider.ConsumeBool();
    uint64_t interval = provider.ConsumeIntegral<uint64_t>();
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    OHOS::AbilityRuntime::WantAgent::WantAgent wantAgent;
    sptr<IRemoteObject> timerCallback = nullptr;
    TimeSystemAbility::GetInstance()->CreateTimer(
        name,
        type,
        repeat,
        disposable,
        autoRestore,
        interval,
        wantAgent,
        timerCallback,
        timerId);

    std::shared_ptr<ITimerInfo> timerOptions = nullptr;
    sptr<IRemoteObject> obj = nullptr;
    TimeSystemAbility::GetInstance()->CreateTimer(timerOptions, obj, timerId);
    TimerPara paras;
    std::function<int32_t (const uint64_t)> callback = nullptr;
    TimeSystemAbility::GetInstance()->CreateTimer(paras, callback, timerId);
    return true;
}

bool CreateTimerWithoutWAFuzzTest(FuzzedDataProvider &provider)
{
    std::string name(provider.ConsumeRandomLengthString());
    int type = provider.ConsumeIntegral<int>();
    bool repeat = provider.ConsumeBool();
    bool disposable = provider.ConsumeBool();
    bool autoRestore = provider.ConsumeBool();
    uint64_t interval = provider.ConsumeIntegral<uint64_t>();
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    sptr<IRemoteObject> timerCallback = nullptr;
    TimeSystemAbility::GetInstance()->CreateTimerWithoutWA(
        name,
        type,
        repeat,
        disposable,
        autoRestore,
        interval,
        timerCallback,
        timerId);
    return true;
}

bool StartTimerFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    uint64_t triggerTime = provider.ConsumeIntegral<uint64_t>();
    TimeSystemAbility::GetInstance()->StartTimer(timerId, triggerTime);
    return true;
}

bool StopTimerFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeSystemAbility::GetInstance()->StopTimer(timerId);
    return true;
}

bool DestroyTimerFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeSystemAbility::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool DestroyTimerAsyncFuzzTest(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeSystemAbility::GetInstance()->DestroyTimerAsync(timerId);
    return true;
}

bool SetTimeFuzzTest(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<uint64_t>();
    int8_t apiVersion = provider.ConsumeIntegral<int8_t>();
    TimeSystemAbility::GetInstance()->SetTime(time, apiVersion);
    return true;
}

bool SetAutoTimeFuzzTest(FuzzedDataProvider &provider)
{
    bool autoTime = provider.ConsumeBool();
    TimeSystemAbility::GetInstance()->SetAutoTime(autoTime);
    return true;
}

bool SetTimeZoneFuzzTest(FuzzedDataProvider &provider)
{
    std::string timeZoneId(provider.ConsumeRandomLengthString());
    int8_t apiVersion = provider.ConsumeIntegral<int8_t>();
    TimeSystemAbility::GetInstance()->SetTimeZone(timeZoneId, apiVersion);
    return true;
}

bool GetTimeZoneFuzzTest(FuzzedDataProvider &provider)
{
    std::string timeZoneId(provider.ConsumeRandomLengthString());
    TimeSystemAbility::GetInstance()->GetTimeZone(timeZoneId);
    return true;
}

bool GetThreadTimeMsFuzzTest(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeSystemAbility::GetInstance()->GetThreadTimeMs(time);
    return true;
}

bool GetThreadTimeNsFuzzTest(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeSystemAbility::GetInstance()->GetThreadTimeNs(time);
    return true;
}

bool AdjustTimerFuzzTest(FuzzedDataProvider &provider)
{
    bool isAdjust = provider.ConsumeBool();
    uint32_t interval = provider.ConsumeIntegral<uint32_t>();
    uint32_t delta = provider.ConsumeIntegral<uint32_t>();
    TimeSystemAbility::GetInstance()->AdjustTimer(isAdjust, interval, delta);
    return true;
}

bool ProxyTimerFuzzTest(FuzzedDataProvider &provider)
{
    int32_t uid = provider.ConsumeIntegral<int32_t>();
    std::vector<int> pidList = convertToVectorInt(provider);
    bool isProxy = provider.ConsumeBool();
    bool needRetrigger = provider.ConsumeBool();
    TimeSystemAbility::GetInstance()->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    return true;
}

bool SetTimerExemptionFuzzTest(FuzzedDataProvider &provider)
{
    std::vector<std::string> nameArr = convertToVectorString(provider);
    bool isExemption = provider.ConsumeBool();
    TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, isExemption);
    return true;
}

bool GetNtpTimeMsFuzzTest(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeSystemAbility::GetInstance()->GetNtpTimeMs(time);
    return true;
}

bool GetRealTimeMsFuzzTest(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeSystemAbility::GetInstance()->GetRealTimeMs(time);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::CreateTimerFuzzTest(provider);
    OHOS::CreateTimerWithoutWAFuzzTest(provider);
    OHOS::StartTimerFuzzTest(provider);
    OHOS::StopTimerFuzzTest(provider);
    OHOS::DestroyTimerFuzzTest(provider);
    OHOS::DestroyTimerAsyncFuzzTest(provider);
    OHOS::SetTimeFuzzTest(provider);
    OHOS::SetAutoTimeFuzzTest(provider);
    OHOS::SetTimeZoneFuzzTest(provider);
    OHOS::GetTimeZoneFuzzTest(provider);
    OHOS::GetThreadTimeMsFuzzTest(provider);
    OHOS::GetThreadTimeNsFuzzTest(provider);
    OHOS::AdjustTimerFuzzTest(provider);
    OHOS::ProxyTimerFuzzTest(provider);
    OHOS::SetTimerExemptionFuzzTest(provider);
    OHOS::GetNtpTimeMsFuzzTest(provider);
    OHOS::GetRealTimeMsFuzzTest(provider);
    return 0;
}

