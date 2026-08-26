/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "timezoneinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#define private public // NOLINT
#include "time_zone_info.h"
#undef private

namespace OHOS {
namespace {
constexpr size_t MAX_TIMEZONE_LENGTH = 64;
constexpr size_t MIN_OPERATION_COUNT = 1;
constexpr size_t MAX_OPERATION_COUNT = 3;

std::string ConsumeTimezone(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> timezoneIds = {
        "", "UTC", "Etc/UTC", "Asia/Shanghai", "Europe/London", "America/New_York", "GMT+08:00",
        "Invalid/Zone", "Asia/Shanghai\r\n",
    };
    if (provider.ConsumeBool()) {
        return timezoneIds[provider.ConsumeIntegralInRange<size_t>(0, timezoneIds.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_TIMEZONE_LENGTH);
}
} // namespace

void RunTimezoneinfoFuzzer(FuzzedDataProvider &provider)
{
    auto &timeZoneInfo = MiscServices::TimeZoneInfo::GetInstance();
    size_t operationCount = provider.ConsumeIntegralInRange<size_t>(MIN_OPERATION_COUNT, MAX_OPERATION_COUNT);
    for (size_t index = 0; index < operationCount; ++index) {
        std::string timezoneId = ConsumeTimezone(provider);
        (void)timeZoneInfo.ConvertTimeZone(timezoneId);
        (void)timeZoneInfo.GetTimeZoneAvailableIDs();
        std::string currentTimezone;
        (void)timeZoneInfo.GetTimezone(currentTimezone);
    }
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimezoneinfoFuzzer(provider);
    return 0;
}
