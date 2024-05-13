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

#include "timeproxytimer_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t ADJUST_TIMER_INTERVAL = 5;


bool FuzzTimeProxyTimer(const uint8_t *rawData, size_t size)
{
    int32_t uid = static_cast<int32_t>(*rawData);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, false);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, false, false);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, false, true);

    std::set<int> pidList;
    pidList.insert(uid);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, false);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, false, false);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, false, true);

    return true;
}

bool FuzzTimeAdjustTimer(const uint8_t *rawData, size_t size)
{
    TimeServiceClient::GetInstance()->AdjustTimer(true, ADJUST_TIMER_INTERVAL);
    TimeServiceClient::GetInstance()->AdjustTimer(false, 0);
    return true;
}

bool FuzzTimeSetTimerExemption(const uint8_t *rawData, size_t size)
{
    std::string name(reinterpret_cast<const char *>(rawData), size);
    std::unordered_set<std::string> nameArr{name};
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    OHOS::FuzzTimeProxyTimer(data, size);
    OHOS::FuzzTimeAdjustTimer(data, size);
    OHOS::FuzzTimeSetTimerExemption(data, size);
    return 0;
}
}