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

#include "timer_proxy.h"
#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int MILLI_TO_SECOND =  1000;
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
            } else {
                itAlarm++;
            }
        }
        if (alarms.empty()) {
            proxyMap_.erase(uid);
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
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto it = proxyUids_.find(uid);
    if (it == proxyUids_.end()) {
        alarm->callback(alarm->id);
        TIME_HILOGI(TIME_MODULE_SERVICE, "Trigger id: %{public}" PRId64 "", alarm->id);
        return;
    }

    TIME_HILOGD(TIME_MODULE_SERVICE, "Alarm is proxy!");
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
}

bool TimerProxy::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start. uid=%{public}d, isProxy=%{public}u, needRetrigger=%{public}u",
        uid, isProxy, needRetrigger);
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

bool TimerProxy::ResetAllProxy(const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    ResetProxyMaps();
    ResetAllProxyWhenElapsed(now, insertAlarmCallback);
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

bool TimerProxy::IsUidProxy(const int32_t uid)
{
    std::lock_guard<std::mutex> lock(proxyMutex_);
    auto it = proxyUids_.find(uid);
    if (it == proxyUids_.end()) {
        return false;
    }
    return true;
}

void TimerProxy::UpdateProxyWhenElapsedForProxyUidMap(const int32_t uid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
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
        itUidTimersMap->second->UpdateWhenElapsed(now, milliseconds(proxyDelayTime_));
        TIME_HILOGD(TIME_MODULE_SERVICE, "Update proxy WhenElapsed for proxy uid map. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            itUidTimersMap->second->uid, itUidTimersMap->second->id,
            itUidTimersMap->second->whenElapsed.time_since_epoch().count(),
            now.time_since_epoch().count());
        insertAlarmCallback(itUidTimersMap->second);
    }
    proxyUids_.insert(std::make_pair(uid, timePointMap));
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
        proxyUids_.erase(uid);
        return true;
    }

    for (auto itProxyUids = proxyUids_.at(uid).begin(); itProxyUids != proxyUids_.at(uid).end(); ++itProxyUids) {
        auto itTimerInfo = uidTimersMap_.at(uid).find(itProxyUids->first);
        if (itTimerInfo == uidTimersMap_.at(uid).end()) {
            continue;
        }
        if (itProxyUids->second > now + milliseconds(MILLI_TO_SECOND)) {
            itTimerInfo->second->UpdateWhenElapsed(itProxyUids->second, milliseconds(0));
        } else {
            itTimerInfo->second->UpdateWhenElapsed(now, milliseconds(MILLI_TO_SECOND));
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

bool TimerProxy::RestoreProxyWhenElapsedForProxyUidMap(const int32_t uid,
    const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
    bool ret = RestoreProxyWhenElapsedByUid(uid, now, insertAlarmCallback);
    if (ret) {
        proxyUids_.erase(uid);
    }
    return ret;
}

void TimerProxy::ResetAllProxyWhenElapsed(const std::chrono::steady_clock::time_point &now,
    std::function<void(std::shared_ptr<TimerInfo> &alarm)> insertAlarmCallback)
{
    std::lock_guard<std::mutex> lockProxy(proxyMutex_);
    for (auto it = proxyUids_.begin(); it!= proxyUids_.end(); ++it) {
        RestoreProxyWhenElapsedByUid(it->first, now, insertAlarmCallback);
    }
    proxyUids_.clear();
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

bool TimerProxy::SetProxyDelayTime(int fd, const int64_t proxyDelayTime)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (proxyDelayTime < 0) {
        dprintf(fd, "set proxy delay time err: %lld\n", proxyDelayTime);
        TIME_HILOGD(TIME_MODULE_SERVICE, "err.");
        return true;
    }

    if (proxyDelayTime == 0) {
        /* ms for 3 days */
        proxyDelayTime_ = 3 * 24 * 60 * 60 * 1000;
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