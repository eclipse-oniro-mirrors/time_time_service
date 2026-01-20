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
#include <fuzzer/FuzzedDataProvider.h>

#include "time_service_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr int MAX_NUM = 20;
constexpr int MAX_LENGTH = 64;

std::set<int> convertToSetInt(FuzzedDataProvider &provider)
{
    std::set<int> pidList;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        int uid = provider.ConsumeIntegral<int>();
        pidList.insert(uid);
    }
    return pidList;
}

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

bool FuzzTimeProxyTimer(FuzzedDataProvider &provider)
{
    int uid = provider.ConsumeIntegral<int>();
    std::set<int> pidList = convertToSetInt(provider);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, pidList, true, true);
    uid = provider.ConsumeIntegral<int>();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, pidList, true, false);
    uid = provider.ConsumeIntegral<int>();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, pidList, false, false);
    uid = provider.ConsumeIntegral<int>();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, pidList, false, true);

    return true;
}

bool FuzzTimeAdjustTimer(FuzzedDataProvider &provider)
{
    size_t interval = provider.ConsumeIntegral<size_t>();
    TimeServiceClient::GetInstance()->AdjustTimer(true, interval, 0);
    TimeServiceClient::GetInstance()->AdjustTimer(false, 0, 0);
    return true;
}

bool FuzzTimeSetTimerExemption(FuzzedDataProvider &provider)
{
    std::unordered_set<std::string> nameArr = convertToUnorderedSetString(provider);
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    nameArr = convertToUnorderedSetString(provider);
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    return true;
}

bool FuzzTimeAdjustPolicy(FuzzedDataProvider &provider)
{
    std::unordered_map<std::string, uint32_t> policyMap = convertToUnorderedMap(provider);
    TimeServiceClient::GetInstance()->SetAdjustPolicy(policyMap);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimeProxyTimer(provider);
    OHOS::FuzzTimeAdjustTimer(provider);
    OHOS::FuzzTimeSetTimerExemption(provider);
    OHOS::FuzzTimeAdjustPolicy(provider);
    return 0;
}
}