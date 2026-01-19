/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "timetesttimer_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "time_service_client.h"
#include "timer_info.h"

using namespace OHOS::MiscServices;

namespace OHOS {
bool FuzzTimeCreateTimer(FuzzedDataProvider &provider)
{
    auto timerInfo = std::make_shared<TimerInfo>();
    int type = provider.ConsumeIntegral<int>();
    uint64_t interval = provider.ConsumeIntegral<uint64_t>();
    bool isRepeat = provider.ConsumeBool();
    timerInfo->SetType(type);
    timerInfo->SetInterval(interval);
    timerInfo->SetRepeat(isRepeat);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeStartTimer(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    uint64_t trigTime = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->StartTimer(timerId, trigTime);
    return true;
}

bool FuzzTimeStopTimer(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    return true;
}

bool FuzzTimeDestroyTimer(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeCreateTimerV9(FuzzedDataProvider &provider)
{
    auto timerInfo = std::make_shared<TimerInfo>();
    int type = provider.ConsumeIntegral<int>();
    uint64_t interval = provider.ConsumeIntegral<uint64_t>();
    bool isRepeat = provider.ConsumeBool();
    timerInfo->SetType(type);
    timerInfo->SetInterval(interval);
    timerInfo->SetRepeat(isRepeat);
    timerInfo->SetAutoRestore(false);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeStartTimerV9(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    uint64_t trigTime = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, trigTime);
    return true;
}

bool FuzzTimeStopTimerV9(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    return true;
}

bool FuzzTimeDestroyTimerV9(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    return true;
}

bool FuzzTimeDestroyTimerAsync(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->DestroyTimerAsync(timerId);
    return true;
}

bool FuzzTimeDestroyTimerAsyncV9(FuzzedDataProvider &provider)
{
    uint64_t timerId = provider.ConsumeIntegral<uint64_t>();
    TimeServiceClient::GetInstance()->DestroyTimerAsyncV9(timerId);
    TimeServiceClient::GetInstance()->ResetAllProxy();
    return true;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimeCreateTimer(provider);
    OHOS::FuzzTimeStartTimer(provider);
    OHOS::FuzzTimeStopTimer(provider);
    OHOS::FuzzTimeDestroyTimer(provider);
    OHOS::FuzzTimeCreateTimerV9(provider);
    OHOS::FuzzTimeStartTimerV9(provider);
    OHOS::FuzzTimeStopTimerV9(provider);
    OHOS::FuzzTimeDestroyTimerV9(provider);
    OHOS::FuzzTimeDestroyTimerAsync(provider);
    OHOS::FuzzTimeDestroyTimerAsyncV9(provider);

    return 0;
}