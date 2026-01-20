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

bool FuzzTimeSetTime(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->SetTime(time);
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->SetTime(time);
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->SetTimeV9(time);
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->SetTimeV9(time);
    int32_t code;
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->SetTime(time, code);
    return true;
}

bool FuzzTimeGetWallTime(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetWallTimeMs(time);
    TimeServiceClient::GetInstance()->GetWallTimeNs();
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetWallTimeNs(time);
    return true;
}

bool FuzzTimeGetBootTime(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetBootTimeMs();
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    TimeServiceClient::GetInstance()->GetBootTimeNs();
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetBootTimeNs(time);
    return true;
}

bool FuzzTimeGetMonotonicTime(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetMonotonicTimeMs(time);
    TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetMonotonicTimeNs(time);
    return true;
}

bool FuzzTimeGetThreadTime(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetThreadTimeMs();
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetThreadTimeMs(time);
    TimeServiceClient::GetInstance()->GetThreadTimeNs();
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetThreadTimeNs(time);
    return true;
}

bool FuzzTimeGetNtpTimeMs(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetNtpTimeMs(time);
    return true;
}

bool FuzzTimeGetRealTimeMs(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetRealTimeMs(time);
    return true;
}

bool FuzzTimeTimeUtilsGetWallTimeMs(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeUtils::GetWallTimeMs(time);
    return true;
}

bool FuzzTimeTimeUtilsGetBootTimeNs(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeUtils::GetBootTimeNs(time);
    TimeUtils::GetBootTimeNs();
    return true;
}

bool FuzzTimeTimeUtilsGetBootTimeMs(FuzzedDataProvider &provider)
{
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeUtils::GetBootTimeNs(time);
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
    OHOS::FuzzTimeSetTimezone(provider);
    OHOS::FuzzTimeGetTimezone(provider);
    OHOS::FuzzTimeSetTime(provider);
    OHOS::FuzzTimeGetWallTime(provider);
    OHOS::FuzzTimeGetBootTime(provider);
    OHOS::FuzzTimeGetMonotonicTime(provider);
    OHOS::FuzzTimeGetThreadTime(provider);
    OHOS::FuzzTimeGetNtpTimeMs(provider);
    OHOS::FuzzTimeGetRealTimeMs(provider);
    OHOS::FuzzTimeTimeUtilsGetWallTimeMs(provider);
    OHOS::FuzzTimeTimeUtilsGetBootTimeNs(provider);
    OHOS::FuzzTimeTimeUtilsGetBootTimeMs(provider);
    return 0;
}