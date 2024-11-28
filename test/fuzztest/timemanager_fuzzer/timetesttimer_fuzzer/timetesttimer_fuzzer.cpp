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

#include "time_service_client.h"
#include "timer_info.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t U64_AT_SIZE = 8;

bool FuzzTimeCreateTimer(int64_t data, size_t size)
{
    auto timerInfo = std::make_shared<TimerInfo>();
    timerInfo->SetType(static_cast<int>(data));
    timerInfo->SetInterval(data);
    timerInfo->SetRepeat(data);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeStartTimer(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->StartTimer(timerId, timerId);
    return true;
}

bool FuzzTimeStopTimer(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    return true;
}

bool FuzzTimeDestroyTimer(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeCreateTimerV9(int64_t data, size_t size)
{
    auto timerInfo = std::make_shared<TimerInfo>();
    timerInfo->SetType(static_cast<int>(data));
    timerInfo->SetInterval(data);
    timerInfo->SetRepeat(data);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    return true;
}

bool FuzzTimeStartTimerV9(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, timerId);
    return true;
}

bool FuzzTimeStopTimerV9(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    return true;
}

bool FuzzTimeDestroyTimerV9(int64_t timerId, size_t size)
{
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
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

    if (size < OHOS::U64_AT_SIZE) {
        return 0;
    }

    auto timerId = static_cast<int64_t>(*data);
    OHOS::FuzzTimeCreateTimer(timerId, size);
    OHOS::FuzzTimeStartTimer(timerId, size);
    OHOS::FuzzTimeStopTimer(timerId, size);
    OHOS::FuzzTimeDestroyTimer(timerId, size);
    OHOS::FuzzTimeCreateTimerV9(timerId, size);
    OHOS::FuzzTimeStartTimerV9(timerId, size);
    OHOS::FuzzTimeStopTimerV9(timerId, size);
    OHOS::FuzzTimeDestroyTimerV9(timerId, size);
    return 0;
}