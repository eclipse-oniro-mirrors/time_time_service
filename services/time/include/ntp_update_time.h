/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef NTP_UPDATE_TIME_H
#define NTP_UPDATE_TIME_H

#include <string>
#include <atomic>

namespace OHOS {
namespace MiscServices {
struct AutoTimeInfo {
    std::string ntpServer;
    std::string ntpServerSpec;
    std::string status;
    int64_t lastUpdateTime;
};

class NtpUpdateTime {
public:
    static NtpUpdateTime &GetInstance();
    static void SetSystemTime();
    void RefreshNetworkTimeByTimer(uint64_t timerId);
    void UpdateNITZSetTime();
    void Stop();
    void Init();
    int32_t MonitorNetwork();
    bool IsValidNITZTime();
    uint64_t GetNITZUpdateTime();

private:
    NtpUpdateTime();
    static void ChangeNtpServerCallback(const char *key, const char *value, void *context);
    static std::vector<std::string> SplitNtpAddrs(const std::string &ntpStr);
    void StartTimer();
    void RefreshNextTriggerTime();
    bool CheckStatus();
    void RegisterSystemParameterListener();
    static void ChangeAutoTimeCallback(const char *key, const char *value, void *context);

    static AutoTimeInfo autoTimeInfo_;
    uint64_t timerId_;
    uint64_t nitzUpdateTimeMilli_;
    uint64_t nextTriggerTime_;
    static std::atomic<bool> isRequesting_;
    int64_t lastNITZUpdateTime_;
};
} // namespace MiscServices
} // namespace OHOS
#endif