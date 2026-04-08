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

#include "timesettimezone_fuzzer.h"
#include "time_common.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_client.h"
#include <fuzzer/FuzzedDataProvider.h>

const int MAX_LENGTH = 64;

using namespace OHOS::MiscServices;

namespace OHOS {

bool FuzzTimeSetTimezone(FuzzedDataProvider &provider)
{
    std::string timeZone = provider.ConsumeRandomLengthString(MAX_LENGTH);
    TimeServiceClient::GetInstance()->SetTimeZone(timeZone);
    timeZone = provider.ConsumeRandomLengthString(MAX_LENGTH);
    TimeServiceClient::GetInstance()->SetTimeZone(timeZone);
    timeZone = provider.ConsumeRandomLengthString(MAX_LENGTH);
    TimeServiceClient::GetInstance()->SetTimeZoneV9(timeZone);
    int32_t code;
    timeZone = provider.ConsumeRandomLengthString(MAX_LENGTH);
    TimeServiceClient::GetInstance()->SetTimeZone(timeZone, code);
    return true;
}

bool FuzzTimeGetTimezone(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetTimeZone();
    std::string timezoneId = provider.ConsumeRandomLengthString(MAX_LENGTH);
    TimeServiceClient::GetInstance()->GetTimeZone(timezoneId);
    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimeSetTimezone(provider);
    OHOS::FuzzTimeGetTimezone(provider);
    return 0;
}
