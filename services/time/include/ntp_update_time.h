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

namespace OHOS {
namespace MiscServices {
struct AutoTimeInfo {
    std::string NTP_SERVER;
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

private:
    NtpUpdateTime();
    static void ChangeNtpServerCallback(const char *key, const char *value, void *context);
    static bool GetAutoTimeInfoFromFile(AutoTimeInfo &info);
    static bool SaveAutoTimeInfoToFile(const AutoTimeInfo &info);
    static std::vector<std::string> InterceptData(const std::string &in);
    void SubscriberNITZTimeChangeCommonEvent();
    void StartTimer();
    void RefreshNextTriggerTime();
    bool CheckStatus();
    void RegisterNtpServerListener();

    static AutoTimeInfo autoTimeInfo_;
    uint64_t timerId_;
    uint64_t nitzUpdateTimeMilli_;
    uint64_t nextTriggerTime_;
};
} // namespace MiscServices
} // namespace OHOS
#endif