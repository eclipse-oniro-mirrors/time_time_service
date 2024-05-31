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

#include <string>
#include <cinttypes>
#include <algorithm>

#include "timer_proxy.h"
#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int MILLI_TO_SECOND =  1000;
/* ms for 3 days */
constexpr int64_t PROXY_DELAY_TIME_IN_MILLI = 3 * 24 * 60 * 60 * 1000;
}

IMPLEMENT_SINGLE_INSTANCE(TimerProxy)

void TimerProxy::RemoveProxy(uint64_t timerNumber, int32_t uid)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto itMap = proxyMap_.find(uid);
    if (itMap != proxyMap_.end()) {
        auto alarms = itMap->second;
        for (auto itAlarm = alarms.begin(); itAlarm != alarms.end();) {
            if ((*itAlarm)->id == timerNumber) {
                alarms.erase(itAlarm);
            }
            itAlarm++;
        }
        if (alarms.empty()) {
            proxyMap_.erase(uid);
        }
    }
}

void TimerProxy::RemovePidProxy(uint64_t timerNumber, int pid)
{
    std::lock_guard<std::mutex> lock(proxyPidMutex_);
    auto itMap = proxyPidMap_.find(pid);
    if (itMap != proxyPidMap_.end()) {
        auto alarms = itMap->second;
        for (auto itAlarm = alarms.begin(); itAlarm != alarms.end();) {
            if ((*itAlarm)->id == timerNumber) {
                alarms.erase(itAlarm);
            }
            itAlarm++;
        }
        if (alarms.empty()) {
            proxyPidMap_.erase(pid);
        }
    }
}

void TimerProxy::CallbackAlarmIfNeed(const std::shared_ptr<TimerInfo> &alarm)
{
    if (alarm == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "callback alarm is nullptr!");
        return;
    }

    int uid = alarm->uid;
    int pid = alarm->pid;
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto uidIt = proxyUids_.find(uid);
    auto pidIt = proxyPids_.find(pid);

    if (uidIt != proxyUids_.end()) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Alarm is uid proxy!");
        auto itMap = proxyMap_.find(uid);
        if (itMap == proxyMap_.end()) {
            std::vector<std::shared_ptr<TimerInfo>> timeInfoVec;
            timeInfoVec.push_back(alarm);
            proxyMap_[uid] = timeInfoVec;
        } else {
            std::vector<std::shared_ptr<TimerInfo>> timeInfoVec = itMap->second;
            timeInfoVec.push_back(alarm);
            proxyMap_[uid] = timeInfoVec;
        }
        return;
    }

    if (pidIt != proxyPids_.end()) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Alarm is pid proxy!");
        auto itMap = proxyPidMap_.find(pid);
        if (itMap == proxyPidMap_.end()) {
            std::vector<std::shared_ptr<TimerInfo>> timeInfoVec;
            timeInfoVec.push_back(alarm);
            proxyPidMap_[pid] = timeInfoVec;
        } else {
            std::vector<std::shared_ptr<TimerInfo>> timeInfoVec = itMap->second;
            timeInfoVec.push_back(alarm);
            proxyPidMap_[pid] = timeInfoVec;
        }
        return;
    }

    alarm->callback(alarm->id);
    TIME_HILOGI(TIME_MODULE_SERVICE, "Trigger id: %{public}" PRId64 "", alarm->id);
    return;
}

bool TimerProxy::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start. uid=%{public}d, isProxy=%{public}u, needRetrigger=%{public}u",
        uid, isProxy, needRetrigger);
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
    if (isProxy) {
        UpdateProxyWhenElapsedForProxyUidMap(uid, now, insertAlarmCallback);
        return true;
    }
    if (!RestoreProxyWhenElapsedForProxyUidMap(uid, now, insertAlarmCallback)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Uid: %{public}d doesn't exist in the proxy list." PRId64 "", uid);
        return false;
    }

    if (!needRetrigger) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ProxyTimer doesn't need retrigger, clear all callbacks!");
        proxyMap_.erase(uid);
        return true;
    }
    auto itMap = proxyMap_.find(uid);
    if (itMap != proxyMap_.end()) {
        auto timeInfoVec = itMap->second;
        for (const auto& alarm : timeInfoVec) {
            if (!alarm->callback) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "ProxyTimer Callback is nullptr!");
                continue;
            }
            alarm->callback(alarm->id);
            TIME_HILOGD(TIME_MODULE_SERVICE, "Shut down proxy, proxyUid: %{public}d, alarmId: %{public}" PRId64 "",
                uid, alarm->id);
        }
        timeInfoVec.clear();
        proxyMap_.erase(uid);
    }
    return true;
}

bool TimerProxy::PidProxyTimer(int pid, bool isProxy, bool needRetrigger,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start. pid=%{public}d, isProxy=%{public}u, needRetrigger=%{public}u",
        pid, isProxy, needRetrigger);

    std::lock_guard<std::mutex> lockProxy(proxyPidMutex_);
    if (isProxy) {
        UpdateProxyWhenElapsedForProxyPidMap(pid, now, insertAlarmCallback);
        return true;
    }

    if (!RestoreProxyWhenElapsedForProxyPidMap(pid, now, insertAlarmCallback)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Pid: %{public}d doesn't exist in the proxy list." PRId64 "", pid);
        return false;
    }

    if (!needRetrigger) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ProxyTimer doesn't need retrigger, clear all callbacks!");
        proxyPidMap_.erase(pid);
        return true;
    }

    auto itMap = proxyPidMap_.find(pid);
    if (itMap != proxyPidMap_.end()) {
        auto timeInfoVec = itMap->second;
        for (const auto& alarm : timeInfoVec) {
            if (!alarm->callback) {
                TIME_HILOGI(TIME_MODULE_SERVICE, "ProxyTimer Callback is nullptr!");
                continue;
            }
            alarm->callback(alarm->id);
            TIME_HILOGD(TIME_MODULE_SERVICE, "Shut down proxy, proxyPid: %{public}d, alarmId: %{public}" PRId64 "",
                pid, alarm->id);
        }
        timeInfoVec.clear();
        proxyPidMap_.erase(pid);
    }
    return true;
}

bool TimerProxy::AdjustTimer(bool isAdjust, uint32_t interval,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(AdjustTimerCallback adjustTimer)> updateTimerDeliveries)
{
    std::lock_guard<std::mutex> lockProxy(adjustMutex_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "adjust timer state: %{public}d, interval: %{public}d", isAdjust, interval);
    auto callback = [this, isAdjust, interval, now] (std::shared_ptr<TimerInfo> timer) {
        if (timer == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "adjust timer is nullptr!");
            return false;
        }
        return isAdjust ? UpdateAdjustWhenElapsed(now, interval, timer) : RestoreAdjustWhenElapsed(timer);
    };
    updateTimerDeliveries(callback);
    if (!isAdjust) {
        adjustTimers_.clear();
    }
    return true;
}

bool TimerProxy::UpdateAdjustWhenElapsed(const std::chrono::steady_clock::time_point &now,
    uint32_t interval, std::shared_ptr<TimerInfo> &timer)
{
    if (IsTimerExemption(timer)) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "adjust exemption timer bundleName: %{public}s",
            timer->bundleName.c_str());
        return false;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "adjust single time id: %{public}" PRId64 ", "
        "uid: %{public}d, bundleName: %{public}s",
        timer->id, timer->uid, timer->bundleName.c_str());
    adjustTimers_.push_back(timer);
    return timer->AdjustTimer(now, interval);
}

bool TimerProxy::RestoreAdjustWhenElapsed(std::shared_ptr<TimerInfo> &timer)
{
    auto it = std::find_if(adjustTimers_.begin(),
                           adjustTimers_.end(),
                           [&timer](const std::shared_ptr<TimerInfo> &compareTimer) {
                               return compareTimer->id == timer->id;
                           });
    if (it == adjustTimers_.end()) {
        return false;
    }
    return timer->RestoreAdjustTimer();
}

bool TimerProxy::SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption)
{
    std::lock_guard<std::mutex> lockProxy(adjustMutex_);
    bool isChanged = false;
    if (!isExemption) {
        for (const auto &name : nameArr) {
            adjustExemptionList_.erase(name);
        }
        return isChanged;
    }
    adjustExemptionList_.insert(nameArr.begin(), nameArr.end());
    return isChanged;
}

bool TimerProxy::IsTimerExemption(std::shared_ptr<TimerInfo> timer)
{
    if (adjustExemptionList_.find(timer->bundleName) != adjustExemptionList_.end()
        && timer->windowLength == milliseconds::zero()) {
        return true;
    }
    return false;
}

void TimerProxy::ResetProxyMaps()
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    for (auto it = proxyMap_.begin(); it != proxyMap_.end(); it++) {
        auto timeInfoVec = it->second;
        for (const auto& alarm : timeInfoVec) {
            if (!alarm->callback) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "Callback is nullptr!");
                continue;
            }
            alarm->callback(alarm->id);
            TIME_HILOGD(TIME_MODULE_SERVICE, "Reset all proxy, proxyUid: %{public}d, alarmId: %{public}" PRId64 "",
                it->first, alarm->id);
        }
        timeInfoVec.clear();
    }
    proxyMap_.clear();
}

void TimerProxy::ResetProxyPidMaps()
{
    std::lock_guard<std::mutex> lock(proxyPidMutex_);
    for (auto it = proxyPidMap_.begin(); it != proxyPidMap_.end(); it++) {
        auto timeInfoVec = it->second;
        for (const auto& alarm : timeInfoVec) {
            if (!alarm->callback) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "Callback is nullptr!");
                continue;
            }
            alarm->callback(alarm->id);
            TIME_HILOGD(TIME_MODULE_SERVICE, "Reset all proxy, proxyPid: %{public}d, alarmId: %{public}" PRId64 "",
                it->first, alarm->id);
        }
        timeInfoVec.clear();
    }
    proxyPidMap_.clear();
}

bool TimerProxy::ResetAllProxy(const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    ResetProxyMaps();
    ResetAllProxyWhenElapsed(now, insertAlarmCallback);
    ResetProxyPidMaps();
    ResetAllPidProxyWhenElapsed(now, insertAlarmCallback);
    return true;
}

void TimerProxy::EraseTimerFromProxyUidMap(const uint64_t id, const uint32_t uid)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "erase timer from proxy timer map, id=%{public}" PRId64 ", uid=%{public}u",
        id, uid);
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto it = proxyUids_.find(uid);
    if (it != proxyUids_.end()) {
        it->second.erase(id);
    }
}

void TimerProxy::EraseTimerFromProxyPidMap(const uint64_t id, const int pid)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "erase timer from proxy timer map, id=%{public}" PRId64 ", pid=%{public}u",
        id, pid);
    std::lock_guard<std::mutex> lock(proxyPidMutex_);
    auto it = proxyPids_.find(pid);
    if (it != proxyPids_.end()) {
        it->second.erase(id);
    }
}

void TimerProxy::EraseAlarmItem(
    const uint64_t id, std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>> &idAlarmsMap)
{
    auto itAlarms = idAlarmsMap.find(id);
    if (itAlarms != idAlarmsMap.end()) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "timer already exists, id=%{public}" PRId64 "", id);
        idAlarmsMap.erase(itAlarms);
    }
}

void TimerProxy::RecordUidTimerMap(const std::shared_ptr<TimerInfo> &alarm, const bool isRebatched)
{
    if (isRebatched) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Record uid timer info map, isRebatched: %{public}d", isRebatched);
        return;
    }
    if (alarm == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "record uid timer map alarm is nullptr!");
        return;
    }

    std::lock_guard<std::mutex> lock(uidTimersMutex_);
    auto it = uidTimersMap_.find(alarm->uid);
    if (it == uidTimersMap_.end()) {
        std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>> idAlarmsMap;
        idAlarmsMap.insert(std::make_pair(alarm->id, alarm));
        uidTimersMap_.insert(std::make_pair(alarm->uid, idAlarmsMap));
        return;
    }

    EraseAlarmItem(alarm->id, it->second);
    it->second.insert(std::make_pair(alarm->id, alarm));
}

void TimerProxy::RecordPidTimerMap(const std::shared_ptr<TimerInfo> &alarm, const bool isRebatched)
{
    if (isRebatched) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Record pid timer info map, isRebatched: %{public}d", isRebatched);
        return;
    }
    if (alarm == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "record pid timer map alarm is nullptr!");
        return;
    }

    std::lock_guard<std::mutex> lock(pidTimersMutex_);
    auto it = pidTimersMap_.find(alarm->pid);
    if (it == pidTimersMap_.end()) {
        std::unordered_map<uint64_t, std::shared_ptr<TimerInfo>> idAlarmsMap;
        idAlarmsMap.insert(std::make_pair(alarm->id, alarm));
        pidTimersMap_.insert(std::make_pair(alarm->pid, idAlarmsMap));
        return;
    }

    EraseAlarmItem(alarm->id, it->second);
    it->second.insert(std::make_pair(alarm->id, alarm));
}

void TimerProxy::RemoveUidTimerMap(const std::shared_ptr<TimerInfo> &alarm)
{
    if (alarm == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "remove uid timer map alarm is nullptr!");
        return;
    }

    std::lock_guard<std::mutex> lock(uidTimersMutex_);
    auto it = uidTimersMap_.find(alarm->uid);
    if (it == uidTimersMap_.end()) {
        return;
    }

    EraseAlarmItem(alarm->id, it->second);
    if (it->second.empty()) {
        uidTimersMap_.erase(it);
    }
}

void TimerProxy::RemovePidTimerMap(const std::shared_ptr<TimerInfo> &alarm)
{
    if (alarm == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "remove pid timer map alarm is nullptr!");
        return;
    }

    std::lock_guard<std::mutex> lock(pidTimersMutex_);
    auto it = pidTimersMap_.find(alarm->pid);
    if (it == pidTimersMap_.end()) {
        return;
    }

    EraseAlarmItem(alarm->id, it->second);
    if (it->second.empty()) {
        pidTimersMap_.erase(it);
    }
}

void TimerProxy::RemoveUidTimerMap(const uint64_t id)
{
    std::lock_guard<std::mutex> lock(uidTimersMutex_);
    for (auto itUidsTimer = uidTimersMap_.begin(); itUidsTimer!= uidTimersMap_.end(); ++itUidsTimer) {
        for (auto itTimerId = itUidsTimer->second.begin(); itTimerId!= itUidsTimer->second.end(); ++itTimerId) {
            if (itTimerId->first != id) {
                continue;
            }

            itUidsTimer->second.erase(itTimerId);
            if (itUidsTimer->second.empty()) {
                uidTimersMap_.erase(itUidsTimer);
            }
            return;
        }
    }
}

void TimerProxy::RemovePidTimerMap(const uint64_t id)
{
    std::lock_guard<std::mutex> lock(pidTimersMutex_);
    for (auto itPidsTimer = pidTimersMap_.begin(); itPidsTimer!= pidTimersMap_.end(); ++itPidsTimer) {
        for (auto itTimerId = itPidsTimer->second.begin(); itTimerId!= itPidsTimer->second.end(); ++itTimerId) {
            if (itTimerId->first != id) {
                continue;
            }

            itPidsTimer->second.erase(itTimerId);
            if (itPidsTimer->second.empty()) {
                pidTimersMap_.erase(itPidsTimer);
            }
            return;
        }
    }
}

bool TimerProxy::IsUidProxy(const int32_t uid)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto it = proxyUids_.find(uid);
    if (it == proxyUids_.end()) {
        return false;
    }
    return true;
}

bool TimerProxy::IsPidProxy(const int32_t pid)
{
    std::lock_guard<std::mutex> lock(proxyPidMutex_);
    auto it = proxyPids_.find(pid);
    if (it == proxyPids_.end()) {
        return false;
    }
    return true;
}

// needs to acquire the lock `proxyMutex_` before calling this method
void TimerProxy::UpdateProxyWhenElapsedForProxyUidMap(const int32_t uid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    auto it = proxyUids_.find(uid);
    if (it != proxyUids_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "uid is already proxy, uid: %{public}d", uid);
        return;
    }

    std::lock_guard<std::mutex> lockUidTimers(uidTimersMutex_);
    if (uidTimersMap_.find(uid) == uidTimersMap_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "uid timer info map not found, uid: %{public}d", uid);
        std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
        proxyUids_.insert(std::make_pair(uid, timePointMap));
        return;
    }

    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
    for (auto itUidTimersMap = uidTimersMap_.at(uid).begin(); itUidTimersMap!= uidTimersMap_.at(uid).end();
        ++itUidTimersMap) {
        timePointMap.insert(std::make_pair(itUidTimersMap->first, itUidTimersMap->second->whenElapsed));
        itUidTimersMap->second->UpdateWhenElapsedFromNow(now, milliseconds(proxyDelayTime_));
        TIME_HILOGD(TIME_MODULE_SERVICE, "Update proxy WhenElapsed for proxy uid map. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            itUidTimersMap->second->uid, itUidTimersMap->second->id,
            itUidTimersMap->second->whenElapsed.time_since_epoch().count(),
            now.time_since_epoch().count());
        insertAlarmCallback(itUidTimersMap->second);
    }
    proxyUids_.insert(std::make_pair(uid, timePointMap));
}

void TimerProxy::UpdateProxyWhenElapsedForProxyPidMap(int pid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    auto it = proxyPids_.find(pid);
    if (it != proxyPids_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "pid is already proxy, pid: %{public}d", pid);
        return;
    }

    std::lock_guard<std::mutex> lockUidTimers(pidTimersMutex_);
    if (pidTimersMap_.find(pid) == pidTimersMap_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "pid timer info map not found, pid: %{public}d", pid);
        std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
        proxyPids_.insert(std::make_pair(pid, timePointMap));
        return;
    }

    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
    for (auto itPidTimersMap = pidTimersMap_.at(pid).begin(); itPidTimersMap!= pidTimersMap_.at(pid).end();
        ++itPidTimersMap) {
        timePointMap.insert(std::make_pair(itPidTimersMap->first, itPidTimersMap->second->whenElapsed));
        itPidTimersMap->second->UpdateWhenElapsedFromNow(now, milliseconds(proxyDelayTime_));
        TIME_HILOGD(TIME_MODULE_SERVICE, "Update proxy WhenElapsed for proxy pid map. "
            "pid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            itPidTimersMap->second->pid, itPidTimersMap->second->id,
            itPidTimersMap->second->whenElapsed.time_since_epoch().count(),
            now.time_since_epoch().count());
        insertAlarmCallback(itPidTimersMap->second);
    }
    proxyPids_.insert(std::make_pair(pid, timePointMap));
}

bool TimerProxy::RestoreProxyWhenElapsedByUid(const int32_t uid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    auto it = proxyUids_.find(uid);
    if (it == proxyUids_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Uid: %{public}d doesn't exist in the proxy list.", uid);
        return false;
    }

    std::lock_guard<std::mutex> lockUidTimers(uidTimersMutex_);
    if (uidTimersMap_.find(uid) == uidTimersMap_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "uid timer info map not found, just erase proxy map. uid: %{public}d", uid);
        return true;
    }

    for (auto itProxyUids = proxyUids_.at(uid).begin(); itProxyUids != proxyUids_.at(uid).end(); ++itProxyUids) {
        auto itTimerInfo = uidTimersMap_.at(uid).find(itProxyUids->first);
        if (itTimerInfo == uidTimersMap_.at(uid).end()) {
            continue;
        }
        if (itProxyUids->second > now + milliseconds(MILLI_TO_SECOND)) {
            auto interval = std::chrono::duration_cast<std::chrono::nanoseconds>(itProxyUids->second - now);
            itTimerInfo->second->UpdateWhenElapsedFromNow(now, interval);
        } else {
            itTimerInfo->second->UpdateWhenElapsedFromNow(now, milliseconds(MILLI_TO_SECOND));
        }
        TIME_HILOGD(TIME_MODULE_SERVICE, "Restore proxy WhenElapsed by uid. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            itTimerInfo->second->uid, itTimerInfo->second->id,
            itTimerInfo->second->whenElapsed.time_since_epoch().count(),
            now.time_since_epoch().count());
        insertAlarmCallback(itTimerInfo->second);
    }

    return true;
}

bool TimerProxy::RestoreProxyWhenElapsedByPid(const int pid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    auto it = proxyPids_.find(pid);
    if (it == proxyPids_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Pid: %{public}d doesn't exist in the proxy list.", pid);
        return false;
    }
    std::lock_guard<std::mutex> lockPidTimers(pidTimersMutex_);
    if (pidTimersMap_.find(pid) == pidTimersMap_.end()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "pid timer info map not found, just erase proxy map. pid: %{public}d", pid);
        return true;
    }
    for (auto itProxyPids = proxyPids_.at(pid).begin(); itProxyPids != proxyPids_.at(pid).end(); ++itProxyPids) {
        auto itTimerInfo = pidTimersMap_.at(pid).find(itProxyPids->first);
        if (itTimerInfo == pidTimersMap_.at(pid).end()) {
            continue;
        }
        if (itProxyPids->second > now + milliseconds(MILLI_TO_SECOND)) {
            auto interval = std::chrono::duration_cast<std::chrono::nanoseconds>(itProxyPids->second - now);
            itTimerInfo->second->UpdateWhenElapsedFromNow(now, interval);
        } else {
            itTimerInfo->second->UpdateWhenElapsedFromNow(now, milliseconds(MILLI_TO_SECOND));
        }
        TIME_HILOGD(TIME_MODULE_SERVICE, "Restore proxy WhenElapsed by pid. "
            "pid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            itTimerInfo->second->pid, itTimerInfo->second->id,
            itTimerInfo->second->whenElapsed.time_since_epoch().count(),
            now.time_since_epoch().count());
        insertAlarmCallback(itTimerInfo->second);
    }

    return true;
}

// needs to acquire the lock `proxyMutex_` before calling this method
bool TimerProxy::RestoreProxyWhenElapsedForProxyUidMap(const int32_t uid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    bool ret = RestoreProxyWhenElapsedByUid(uid, now, insertAlarmCallback);
    if (ret) {
        proxyUids_.erase(uid);
    }
    return ret;
}

bool TimerProxy::RestoreProxyWhenElapsedForProxyPidMap(const int pid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    bool ret = RestoreProxyWhenElapsedByPid(pid, now, insertAlarmCallback);
    if (ret) {
        proxyPids_.erase(pid);
    }
    return ret;
}


void TimerProxy::ResetAllProxyWhenElapsed(const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
    for (auto it = proxyUids_.begin(); it != proxyUids_.end(); ++it) {
        RestoreProxyWhenElapsedByUid(it->first, now, insertAlarmCallback);
    }
    proxyUids_.clear();
}

void TimerProxy::ResetAllPidProxyWhenElapsed(const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    std::lock_guard<std::mutex> lockProxy(proxyPidMutex_);
    for (auto it = proxyPids_.begin(); it != proxyPids_.end(); ++it) {
        RestoreProxyWhenElapsedByPid(it->first, now, insertAlarmCallback);
    }
    proxyPids_.clear();
}

bool TimerProxy::ShowProxyTimerInfo(int fd, const int64_t now)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
    dprintf(fd, "current time %lld\n", now);
    for (auto itProxyUids = proxyUids_.begin(); itProxyUids != proxyUids_.end(); ++itProxyUids) {
        dprintf(fd, " - proxy uid = %lu\n", itProxyUids->first);
        for (auto itTimerIdMap = itProxyUids->second.begin(); itTimerIdMap != itProxyUids->second.end();
            ++itTimerIdMap) {
            dprintf(fd, "   * save timer id          = %llu\n", itTimerIdMap->first);
            dprintf(fd, "   * save timer whenElapsed = %lld\n", itTimerIdMap->second.time_since_epoch().count());
        }
    }
    std::lock_guard<std::mutex> lockPidProxy(proxyPidMutex_);
    dprintf(fd, "current time %lld\n", now);
    for (auto itProxyPids = proxyPids_.begin(); itProxyPids != proxyPids_.end(); ++itProxyPids) {
        dprintf(fd, " - proxy pid = %lu\n", itProxyPids->first);
        for (auto itTimerIdMap = itProxyPids->second.begin(); itTimerIdMap != itProxyPids->second.end();
            ++itTimerIdMap) {
            dprintf(fd, "   * save timer id          = %llu\n", itTimerIdMap->first);
            dprintf(fd, "   * save timer whenElapsed = %lld\n", itTimerIdMap->second.time_since_epoch().count());
        }
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerProxy::ShowUidTimerMapInfo(int fd, const int64_t now)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lockProxy(uidTimersMutex_);
    dprintf(fd, "current time %lld\n", now);
    for (auto itTimerInfoMap = uidTimersMap_.begin(); itTimerInfoMap != uidTimersMap_.end(); ++itTimerInfoMap) {
            dprintf(fd, " - uid = %lu\n", itTimerInfoMap->first);
        for (auto itTimerInfo = itTimerInfoMap->second.begin(); itTimerInfo != itTimerInfoMap->second.end();
            ++itTimerInfo) {
            dprintf(fd, "   * timer id          = %llu\n", itTimerInfo->second->id);
            dprintf(fd, "   * timer whenElapsed = %lld\n", itTimerInfo->second->whenElapsed.time_since_epoch().count());
        }
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerProxy::ShowPidTimerMapInfo(int fd, const int64_t now)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lockProxy(pidTimersMutex_);
    dprintf(fd, "current time %lld\n", now);
    for (auto itTimerInfoMap = pidTimersMap_.begin(); itTimerInfoMap != pidTimersMap_.end(); ++itTimerInfoMap) {
            dprintf(fd, " - pid = %lu\n", itTimerInfoMap->first);
        for (auto itTimerInfo = itTimerInfoMap->second.begin(); itTimerInfo != itTimerInfoMap->second.end();
            ++itTimerInfo) {
            dprintf(fd, "   * timer id          = %llu\n", itTimerInfo->second->id);
            dprintf(fd, "   * timer whenElapsed = %lld\n", itTimerInfo->second->whenElapsed.time_since_epoch().count());
        }
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}


void TimerProxy::ShowAdjustTimerInfo(int fd)
{
    std::lock_guard<std::mutex> lockProxy(adjustMutex_);
    dprintf(fd, "show adjust timer");
    for (auto timer : adjustTimers_) {
        dprintf(fd, " * timer id            = %lu\n", timer->id);
        dprintf(fd, " * timer uid           = %d\n\n", timer->uid);
        dprintf(fd, " * timer bundleName           = %s\n\n", timer->bundleName.c_str());
        dprintf(fd, " * timer originWhenElapsed           = %lld\n\n", timer->originWhenElapsed);
        dprintf(fd, " * timer whenElapsed           = %lld\n\n", timer->whenElapsed);
        dprintf(fd, " * timer originMaxWhenElapsed           = %lld\n\n", timer->originMaxWhenElapsed);
        dprintf(fd, " * timer maxWhenElapsed           = %lld\n\n", timer->maxWhenElapsed);
    }
}

bool TimerProxy::SetProxyDelayTime(int fd, const int64_t proxyDelayTime)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (proxyDelayTime < 0) {
        dprintf(fd, "set proxy delay time err: %lld\n", proxyDelayTime);
        TIME_HILOGD(TIME_MODULE_SERVICE, "err.");
        return true;
    }

    if (proxyDelayTime == 0) {
        proxyDelayTime_ = PROXY_DELAY_TIME_IN_MILLI;
    } else {
        proxyDelayTime_ = proxyDelayTime;
    }
    dprintf(fd, "proxy delay time is set to %lld ms\n", proxyDelayTime_);

    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerProxy::ShowProxyDelayTime(int fd)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    dprintf(fd, "proxy delay time: %lld ms\n", proxyDelayTime_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

int64_t TimerProxy::GetProxyDelayTime() const
{
    return proxyDelayTime_;
}
} // MiscServices
} // OHOS