/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "time_zone_info.h"

namespace OHOS {
namespace MiscServices {
namespace {
    constexpr const char *TIMEZONE_KEY = "persist.time.timezone";
    const int TIMEZONE_OK = 0;
    const int CONFIG_LEN = 35;
    const int HOUR_TO_MILLI = 60;
}

TimeZoneInfo::TimeZoneInfo()
{
    std::vector<struct zoneInfoEntry> timezoneList = { { "Antarctica/McMurdo", "AQ", 12 },
        { "America/Argentina/Buenos_Aires", "AR", -3 }, { "Australia/Sydney", "AU", 10 },
        { "America/Noronha", "BR", -2 }, { "America/St_Johns", "CA", -3 }, { "Africa/Kinshasa", "CD", 1 },
        { "America/Santiago", "CL", -3 }, { "Asia/Shanghai", "CN", 8 }, { "Asia/Nicosia", "CY", 3 },
        { "Europe/Berlin", "DE", 2 }, { "America/Guayaquil", "CEST", -5 }, { "Europe/Madrid", "ES", 2 },
        { "Pacific/Pohnpei", "FM", 11 }, { "America/Godthab", "GL", -2 }, { "Asia/Jakarta", "ID", 7 },
        { "Pacific/Tarawa", "KI", 12 }, { "Asia/Almaty", "KZ", 6 }, { "Pacific/Majuro", "MH", 12 },
        { "Asia/Ulaanbaatar", "MN", 8 }, { "America/Mexico_City", "MX", -5 }, { "Asia/Kuala_Lumpur", "MY", 8 },
        { "Pacific/Auckland", "NZ", 12 }, { "Pacific/Tahiti", "PF", -10 }, { "Pacific/Port_Moresby", "PG", 10 },
        { "Asia/Gaza", "PS", 3 }, { "Europe/Lisbon", "PT", 1 }, { "Europe/Moscow", "RU", 3 },
        { "Europe/Kiev", "UA", 3 }, { "Pacific/Wake", "UM", 12 }, { "America/New_York", "US", -4 },
        { "Asia/Tashkent", "UZ", 5 } };

    for (const auto &tz : timezoneList) {
        timezoneInfoMap_[tz.ID] = tz;
    }
}

TimeZoneInfo::~TimeZoneInfo()
{
    timezoneInfoMap_.clear();
}

void TimeZoneInfo::Init()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Start.");
    char value[CONFIG_LEN] = "Asia/Shanghai";
    if (GetParameter(TIMEZONE_KEY, "", value, CONFIG_LEN) < TIMEZONE_OK) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found timezone from system parameter.");
    }

    if (!SetTimezoneToKernel(value)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init Set kernel failed.");
    }
    curTimezoneId_ = value;
    TIME_HILOGI(TIME_MODULE_SERVICE, "Timezone value: %{public}s", value);
}

bool TimeZoneInfo::SetTimezone(std::string timezoneId)
{
    if (curTimezoneId_ == timezoneId) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Same Timezone has been set.");
        return true;
    }

    auto errNo = SetParameter(TIMEZONE_KEY, timezoneId.c_str());
    if (errNo > TIMEZONE_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "SetTimezone timezoneId: %{public}d: %{public}s", errNo, timezoneId.c_str());
        return false;
    }

    if (!SetTimezoneToKernel(timezoneId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "SetTimezone Set kernel failed.");
        return false;
    }
    curTimezoneId_ = timezoneId;
    return true;
}

bool TimeZoneInfo::GetTimezone(std::string &timezoneId)
{
    timezoneId = curTimezoneId_;
    return true;
}

bool TimeZoneInfo::SetTimezoneToKernel(std::string timezoneId)
{
    auto itEntry = timezoneInfoMap_.find(timezoneId);
    if (itEntry != timezoneInfoMap_.end()) {
        auto offset = itEntry->second.utcOffsetHours;
        struct timezone tz;
        tz.tz_minuteswest = offset * HOUR_TO_MILLI;
        tz.tz_dsttime = 0;

        int result = settimeofday(NULL, &tz);
        if (result < 0) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Settimeofday timezone fail: %{public}d.", result);
            return false;
        } else {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Timezone offset: %{public}d", offset);
            return true;
        }
    }
    return false;
}
}
}