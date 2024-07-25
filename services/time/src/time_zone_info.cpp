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

#include <cerrno>
#include <climits>
#include <fstream>
#include <sys/stat.h>
#include "time_zone_info.h"
#include "ipc_skeleton.h"
#include "time_file_utils.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr const char *TIMEZONE_KEY = "persist.time.timezone";
constexpr const char *TIMEZONE_LIST_CONFIG_PATH = "/system/etc/zoneinfo/timezone_list.cfg";
constexpr const char *DISTRO_TIMEZONE_LIST_CONFIG = "/system/etc/tzdata_distro/timezone_list.cfg";
const int TIMEZONE_OK = 0;
const int CONFIG_LEN = 35;
const int HOUR_TO_MIN = 60;
} // namespace

TimeZoneInfo &TimeZoneInfo::GetInstance()
{
    static TimeZoneInfo instance;
    return instance;
}

void TimeZoneInfo::Init()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Start.");
    char value[CONFIG_LEN] = "Asia/Shanghai";
    if (GetParameter(TIMEZONE_KEY, "", value, CONFIG_LEN) < TIMEZONE_OK) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found timezone from system parameter.");
    }
    if (!SetTimezone(value)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init Set kernel failed.");
    }
    curTimezoneId_ = value;
    TIME_HILOGD(TIME_MODULE_SERVICE, "Timezone value: %{public}s", value);
}

bool TimeZoneInfo::SetTimezone(const std::string &timezoneId)
{
    std::lock_guard<std::mutex> lock(timezoneMutex_);
    if (curTimezoneId_ == timezoneId) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Same Timezone has been set.");
        return true;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Set timezone : %{public}s, Current timezone : %{public}s, uid: %{public}d",
        timezoneId.c_str(), curTimezoneId_.c_str(), IPCSkeleton::GetCallingUid());
    std::set<std::string> availableTimeZoneIDs = GetTimeZoneAvailableIDs();
    if (availableTimeZoneIDs.find(timezoneId) == availableTimeZoneIDs.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Invalid timezone");
        return false;
    }
    setenv("TZ", timezoneId.c_str(), 1);
    tzset();
    if (!SetTimezoneToKernel()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "SetTimezone Set kernel failed.");
        return false;
    }
    auto errNo = SetParameter(TIMEZONE_KEY, timezoneId.c_str());
    if (errNo > TIMEZONE_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "SetTimezone timezoneId: %{public}d: %{public}s", errNo, timezoneId.c_str());
        return false;
    }
    curTimezoneId_ = timezoneId;
    return true;
}

std::set<std::string> TimeZoneInfo::GetTimeZoneAvailableIDs()
{
    std::set<std::string> availableTimeZoneIDs;
    struct stat s;
    const char *tzIdConfigPath = stat(DISTRO_TIMEZONE_LIST_CONFIG, &s) == 0 ?
        DISTRO_TIMEZONE_LIST_CONFIG : TIMEZONE_LIST_CONFIG_PATH;
    std::unique_ptr<char[]> resolvedPath = std::make_unique<char[]>(PATH_MAX + 1);
    TIME_HILOGE(TIME_MODULE_SERVICE, "Available TimeZone config path is %{public}s", tzIdConfigPath);
    if (realpath(tzIdConfigPath, resolvedPath.get()) == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "GetTimeZoneAvailableIDs get realpath failed, errno: %{public}d.", errno);
        return availableTimeZoneIDs;
    }
    std::ifstream file(resolvedPath.get());
    if (!file.good()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "GetTimeZoneAvailableIDs open file failed.");
        return availableTimeZoneIDs;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.length() == 0) {
            break;
        }
        line = line.substr(0, line.find_last_not_of("\r\n") + 1);
        availableTimeZoneIDs.insert(line);
    }
    file.close();
    return availableTimeZoneIDs;
}

bool TimeZoneInfo::GetTimezone(std::string &timezoneId)
{
    timezoneId = curTimezoneId_;
    return true;
}

bool TimeZoneInfo::SetTimezoneToKernel()
{
    time_t t = time(nullptr);
    struct tm *localTime = localtime(&t);
    struct timezone tz {};
    if (localTime == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "localtime is nullptr errornum: %{public}s.", strerror(errno));
        return false;
    }
    tz.tz_minuteswest = -localTime->tm_gmtoff / HOUR_TO_MIN;
    tz.tz_dsttime = 0;
    int result = settimeofday(nullptr, &tz);
    if (result < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Settimeofday timezone fail: %{public}d.", result);
        return false;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "Settimeofday timezone success ");
    return true;
}
} // namespace MiscServices
} // namespace OHOS