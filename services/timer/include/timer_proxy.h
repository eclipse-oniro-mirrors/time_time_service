/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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
#ifndef TIMER_PROXY_H
#define TIMER_PROXY_H

#include <chrono>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <stdint.h>

#include "single_instance.h"
#include "timer_info.h"

namespace OHOS {
namespace MiscServices {
using AdjustTimerCallback = std::function<bool(std::shared_ptr<TimerInfo> timer)>;
class TimerProxy {
    DECLARE_SINGLE_INSTANCE(TimerProxy)
public:
    void RemoveProxy(uint64_t timerNumber, int32_t uid);
    void RemovePidProxy(uint64_t timerNumber, int32_t uid);
    void CallbackAlarmIfNeed(const std::shared_ptr<TimerInfo> &alarm);
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool PidProxyTimer(int pidList, bool isProxy, bool needRetrigger,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool AdjustTimer(bool isAdjust, uint32_t interval,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(AdjustTimerCallback adjustTimer)> updateTimerDeliveries);
    bool SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption);
    bool IsTimerExemption(std::shared_ptr<TimerInfo> time);
    bool ResetAllProxy(const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    void EraseTimerFromProxyUidMap(const uint64_t id, const uint32_t uid);
    void EraseTimerFromProxyPidMap(const uint64_t id, const int pid);
    void RecordUidTimerMap(const std::shared_ptr<TimerInfo> &alarm, const bool isRebatched);
    void RecordPidTimerMap(const std::shared_ptr<TimerInfo> &alarm, const bool isRebatched);
    void RemoveUidTimerMap(const std::shared_ptr<TimerInfo> &alarm);
    void RemovePidTimerMap(const std::shared_ptr<TimerInfo> &alarm);
    void RemoveUidTimerMap(const uint64_t id);
    void RemovePidTimerMap(const uint64_t id);
    bool IsUidProxy(const int32_t uid);
    bool IsPidProxy(const int32_t pid);
    bool ShowProxyTimerInfo(int fd, const int64_t now);
    bool ShowPidProxyTimerInfo(int fd, const int64_t now);
    bool ShowUidTimerMapInfo(int fd, const int64_t now);
    bool ShowPidTimerMapInfo(int fd, const int64_t now);
    bool SetProxyDelayTime(int fd, const int64_t proxyDelayTime);
    bool ShowProxyDelayTime(int fd);
    void ShowAdjustTimerInfo(int fd);
    int64_t GetProxyDelayTime() const;

private:
    void ResetProxyMaps();
    void ResetProxyPidMaps();
    void EraseAlarmItem(
        const uint64_t id, std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>> &idAlarmsMap);
    void UpdateProxyWhenElapsedForProxyUidMap(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    void UpdateProxyWhenElapsedForProxyPidMap(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool UpdateAdjustWhenElapsed(const std::chrono::steady_clock::time_point &now,
        uint32_t interval, std::shared_ptr<TimerInfo> &timer);
    bool RestoreAdjustWhenElapsed(std::shared_ptr<TimerInfo> &timer);
    bool RestoreProxyWhenElapsedByUid(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool RestoreProxyWhenElapsedByPid(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool RestoreProxyWhenElapsedForProxyUidMap(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    bool RestoreProxyWhenElapsedForProxyPidMap(const int32_t uid,
        const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    void ResetAllProxyWhenElapsed(const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);
    void ResetAllPidProxyWhenElapsed(const std::chrono::steady_clock::time_point &now,
        std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback);

    std::mutex uidTimersMutex_;
    std::mutex pidTimersMutex_;
    /* <uid, <id, alarm ptr>> */
    std::unordered_map<int32_t, std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>>> uidTimersMap_ {};
    std::unordered_map<int32_t, std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>>> pidTimersMap_ {};
    std::mutex proxyMutex_;
    std::mutex proxyPidMutex_;
    /* <uid, <id, trigger time>> */
    std::unordered_map<int32_t, std::unordered_map<uint64_t, std::chrono::steady_clock::time_point>> proxyUids_ {};
    std::unordered_map<int32_t, std::unordered_map<uint64_t, std::chrono::steady_clock::time_point>> proxyPids_ {};
    std::map<int32_t, std::vector<std::shared_ptr<TimerInfo>>> proxyMap_ {};
    std::map<int32_t, std::vector<std::shared_ptr<TimerInfo>>> proxyPidMap_ {};
    std::mutex adjustMutex_;
    std::unordered_set<std::string> adjustExemptionList_ {};
    std::vector<std::shared_ptr<TimerInfo>> adjustTimers_ {};
    /* ms for 3 days */
    int64_t proxyDelayTime_ = 3 * 24 * 60 * 60 * 1000;
}; // timer_proxy
} // MiscServices
} // OHOS

#endif // TIMER_PROXY_H