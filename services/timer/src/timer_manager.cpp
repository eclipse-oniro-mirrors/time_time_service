/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "timer_manager.h"

#include <algorithm>
#include <ctime>
#include <iostream>
#include <sys/time.h>
#include <utility>
#include <vector>

#include "system_ability_definition.h"
#ifdef DEVICE_STANDBY_ENABLE
#include "allow_type.h"
#include "standby_service_client.h"
#endif
#include "ipc_skeleton.h"
#include "time_file_utils.h"
#include "time_permission.h"
#include "timer_proxy.h"
#include "time_sysevent.h"
#include "os_account.h"
#include "os_account_manager.h"
#include "cjson_helper.h"
#ifdef POWER_MANAGER_ENABLE
#include "time_system_ability.h"
#endif

namespace OHOS {
namespace MiscServices {
using namespace std::chrono;
using namespace OHOS::AppExecFwk;
namespace {
constexpr uint32_t TIME_CHANGED_BITS = 16;
constexpr uint32_t TIME_CHANGED_MASK = 1 << TIME_CHANGED_BITS;
constexpr int64_t MAX_MILLISECOND = std::numeric_limits<int64_t>::max() / 1000000;
const int ONE_THOUSAND = 1000;
const float_t BATCH_WINDOW_COE = 0.75;
const auto ZERO_FUTURITY = seconds(0);
const auto MIN_INTERVAL_ONE_SECONDS = seconds(1);
const auto MAX_INTERVAL = hours(24 * 365);
const auto INTERVAL_HOUR = hours(1);
const auto INTERVAL_HALF_DAY = hours(12);
const auto MIN_FUZZABLE_INTERVAL = milliseconds(10000);
const int NANO_TO_SECOND =  1000000000;
const int WANTAGENT_CODE_ELEVEN = 11;
const int WANT_RETRY_TIMES = 6;
const int WANT_RETRY_INTERVAL = 1;
const int SYSTEM_USER_ID  = 0;
// an error code of ipc which means peer end is dead
constexpr int PEER_END_DEAD = 29189;
constexpr int TIMER_ALARM_COUNT = 50;
constexpr int MAX_TIMER_ALARM_COUNT = 100;
constexpr int TIMER_ALRAM_INTERVAL = 60;
constexpr int TIMER_COUNT_TOP_NUM = 5;
static const std::vector<std::string> ALL_DATA = { "timerId", "type", "flag", "windowLength", "interval", \
                                                   "uid", "bundleName", "wantAgent", "state", "triggerTime" };

#ifdef POWER_MANAGER_ENABLE
constexpr int64_t USE_LOCK_ONE_SEC_IN_NANO = 1 * NANO_TO_SECOND;
constexpr int64_t USE_LOCK_TIME_IN_NANO = 2 * NANO_TO_SECOND;
constexpr int32_t NANO_TO_MILLI = 1000000;
constexpr int64_t ONE_HUNDRED_MILLI = 100000000; // 100ms
const int POWER_RETRY_TIMES = 10;
const int POWER_RETRY_INTERVAL = 10000;
#endif

#ifdef DEVICE_STANDBY_ENABLE
const int REASON_NATIVE_API = 0;
const int REASON_APP_API = 1;
#endif
}

std::mutex TimerManager::instanceLock_;
TimerManager* TimerManager::instance_ = nullptr;

extern bool AddBatchLocked(std::vector<std::shared_ptr<Batch>> &list, const std::shared_ptr<Batch> &batch);
extern steady_clock::time_point MaxTriggerTime(steady_clock::time_point now,
                                               steady_clock::time_point triggerAtTime,
                                               milliseconds interval);

TimerManager::TimerManager(std::shared_ptr<TimerHandler> impl)
    : random_ {static_cast<uint64_t>(time(nullptr))},
      runFlag_ {true},
      handler_ {std::move(impl)},
      lastTimeChangeClockTime_ {system_clock::time_point::min()},
      lastTimeChangeRealtime_ {steady_clock::time_point::min()},
      lastTimerOutOfRangeTime_ {steady_clock::time_point::min()}
{
    alarmThread_.reset(new std::thread([this] { this->TimerLooper(); }));
}

TimerManager* TimerManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            auto impl = TimerHandler::Create();
            if (impl == nullptr) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "Create Timer handle failed.");
                return nullptr;
            }
            instance_ = new TimerManager(impl);
            std::vector<std::string> bundleList = TimeFileUtils::GetBundleList();
            if (!bundleList.empty()) {
                NEED_RECOVER_ON_REBOOT = bundleList;
            }
        }
    }
    if (instance_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Create Timer manager failed.");
    }
    return instance_;
}

// needs to acquire the lock `entryMapMutex_` before calling this method
void TimerManager::AddTimerName(int uid, std::string name, uint64_t timerId)
{
    if (timerNameMap_.find(uid) == timerNameMap_.end() || timerNameMap_[uid].find(name) == timerNameMap_[uid].end()) {
        timerNameMap_[uid][name] = timerId;
        TIME_HILOGD(TIME_MODULE_SERVICE, "record name: %{public}s id %{public}" PRId64 "", name.c_str(), timerId);
        return;
    }
    auto oldTimerId = timerNameMap_[uid][name];
    timerNameMap_[uid][name] = timerId;
    bool needRecover;
    StopTimerInnerLocked(true, oldTimerId, needRecover);
    UpdateOrDeleteDatabase(true, oldTimerId, needRecover);
    TIME_HILOGW(TIME_MODULE_SERVICE, "name: %{public}s in %{public}d already exist, destory timer %{public}" PRId64 "",
        name.c_str(), uid, oldTimerId);
    return;
}

// needs to acquire the lock `entryMapMutex_` before calling this method
void TimerManager::DeleteTimerName(int uid, std::string name, uint64_t timerId)
{
    auto nameIter = timerNameMap_.find(uid);
    if (nameIter == timerNameMap_.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "NameMap has no uid %{public}d", uid);
        return;
    }
    auto timerIter = nameIter->second.find(name);
    if (timerIter == nameIter->second.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "NameMap has no name:%{public}s uid: %{public}d", name.c_str(), uid);
        return;
    }
    if (timerIter->second == timerId) {
        timerNameMap_[uid].erase(timerIter);
        return;
    }
    TIME_HILOGW(TIME_MODULE_SERVICE,
        "timer %{public}" PRId64 " not exist in map, name:%{public}s uid%{public}d", timerId, name.c_str(), uid);
}

int32_t TimerManager::CreateTimer(TimerPara &paras,
                                  std::function<int32_t (const uint64_t)> callback,
                                  std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                                  int uid,
                                  int pid,
                                  uint64_t &timerId,
                                  DatabaseType type)
{
    TIME_HILOGD(TIME_MODULE_SERVICE,
                "Create timer: %{public}d windowLength:%{public}" PRId64 "interval:%{public}" PRId64 "flag:%{public}d"
                "uid:%{public}d pid:%{public}d timerId:%{public}" PRId64 "", paras.timerType, paras.windowLength,
                paras.interval, paras.flag, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid(), timerId);
    std::string bundleName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    if (bundleName.empty()) {
        bundleName = TimeFileUtils::GetNameByPid(IPCSkeleton::GetCallingPid());
    }
    auto timerName = paras.name;
    std::shared_ptr<TimerEntry> timerInfo;
    {
        std::lock_guard<std::mutex> lock(entryMapMutex_);
        while (timerId == 0) {
            // random_() needs to be protected in a lock.
            timerId = random_();
        }
        timerInfo = std::make_shared<TimerEntry>(TimerEntry {
            timerName,
            timerId,
            paras.timerType,
            paras.windowLength,
            paras.interval,
            paras.flag,
            paras.autoRestore,
            std::move(callback),
            wantAgent,
            uid,
            pid,
            bundleName
        });
        timerEntryMap_.insert(std::make_pair(timerId, timerInfo));
        IncreaseTimerCount(uid);
        if (timerName != "") {
            AddTimerName(uid, timerName, timerId);
        }
    }
    if (type == NOT_STORE) {
        return E_TIME_OK;
    } else if (CheckNeedRecoverOnReboot(bundleName, paras.timerType, paras.autoRestore)) {
        CjsonHelper::GetInstance().Insert(std::string(HOLD_ON_REBOOT), timerInfo);
    } else {
        CjsonHelper::GetInstance().Insert(std::string(DROP_ON_REBOOT), timerInfo);
    }
    return E_TIME_OK;
}

void TimerManager::ReCreateTimer(uint64_t timerId, std::shared_ptr<TimerEntry> timerInfo)
{
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    timerEntryMap_.insert(std::make_pair(timerId, timerInfo));
    if (timerInfo->name != "") {
        AddTimerName(timerInfo->uid, timerInfo->name, timerId);
    }
    IncreaseTimerCount(timerInfo->uid);
}

int32_t TimerManager::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    std::shared_ptr<TimerEntry> timerInfo;
    {
        std::lock_guard<std::mutex> lock(entryMapMutex_);
        auto it = timerEntryMap_.find(timerId);
        if (it == timerEntryMap_.end()) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Timer id not found: %{public}" PRId64 "", timerId);
            return E_TIME_NOT_FOUND;
        }
        timerInfo = it->second;
        TIME_HILOGI(TIME_MODULE_SERVICE,
            "id: %{public}" PRIu64 " typ:%{public}d len: %{public}" PRId64 " int: %{public}" PRId64 " "
            "flg :%{public}d trig: %{public}s uid:%{public}d pid:%{public}d",
            timerId, timerInfo->type, timerInfo->windowLength, timerInfo->interval, timerInfo->flag,
            std::to_string(triggerTime).c_str(), IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
        {
            // To prevent the same ID from being started repeatedly,
            // the later start overwrites the earlier start.
            std::lock_guard<std::mutex> lock(mutex_);
            RemoveLocked(timerId, false);
        }
        SetHandler(timerInfo->name, timerInfo->id, timerInfo->type, triggerTime, timerInfo->windowLength,
            timerInfo->interval, timerInfo->flag, timerInfo->autoRestore, timerInfo->callback, timerInfo->wantAgent,
            timerInfo->uid, timerInfo->pid, timerInfo->bundleName);
    }
    auto tableName = (CheckNeedRecoverOnReboot(timerInfo->bundleName, timerInfo->type, timerInfo->autoRestore)
                      ? HOLD_ON_REBOOT
                      : DROP_ON_REBOOT);
    CjsonHelper::GetInstance().UpdateTrigger(tableName,
                                             static_cast<int64_t>(timerId),
                                             static_cast<int64_t>(triggerTime));
    return E_TIME_OK;
}

void TimerManager::IncreaseTimerCount(int uid)
{
    auto it = std::find_if(timerCount_.begin(), timerCount_.end(),
        [uid](const std::pair<int32_t, size_t>& pair) {
            return pair.first == uid;
        });
    if (it == timerCount_.end()) {
        timerCount_.push_back(std::make_pair(uid, 1));
    } else {
        it->second++;
    }
    CheckTimerCount();
}

void TimerManager::DecreaseTimerCount(int uid)
{
    auto it = std::find_if(timerCount_.begin(), timerCount_.end(),
        [uid](const std::pair<int32_t, size_t>& pair) {
            return pair.first == uid;
        });
    if (it == timerCount_.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "uid: %{public}d has no timer", uid);
    } else {
        it->second--;
    }
}

void TimerManager::CheckTimerCount()
{
    int count = static_cast<int>(timerEntryMap_.size());
    if (count > (timerOutOfRangeTimes_ + 1) * TIMER_ALARM_COUNT) {
        timerOutOfRangeTimes_ += 1;
        TIME_HILOGI(TIME_MODULE_SERVICE, "%{public}d timer in system", count);
        ShowTimerCountByUid();
        lastTimerOutOfRangeTime_ = GetBootTimeNs();
        return;
    }
    auto currentBootTime = GetBootTimeNs();
    if (count > MAX_TIMER_ALARM_COUNT &&
        currentBootTime - lastTimerOutOfRangeTime_ > std::chrono::minutes(TIMER_ALRAM_INTERVAL)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "%{public}d timer in system", count);
        ShowTimerCountByUid();
        lastTimerOutOfRangeTime_ = currentBootTime;
        return;
    }
}

void TimerManager::ShowTimerCountByUid()
{
    std::string uidStr = "";
    std::string countStr = "";
    auto size = static_cast<int>(timerCount_.size());
    std::sort(timerCount_.begin(), timerCount_.end(),
        [](const std::pair<int32_t, int32_t>& a, const std::pair<int32_t, int32_t>& b) {
            return a.second > b.second;
        });
    auto limitedSize = (size > TIMER_COUNT_TOP_NUM) ? TIMER_COUNT_TOP_NUM : size;
    for (auto it = timerCount_.begin(); it != timerCount_.begin() + limitedSize; ++it) {
        uidStr = uidStr + std::to_string(it->first) + " ";
        countStr = countStr + std::to_string(it->second) + " ";
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Top uid:[%{public}s], nums:[%{public}s]", uidStr.c_str(), countStr.c_str());
}

int32_t TimerManager::StopTimer(uint64_t timerId)
{
    return StopTimerInner(timerId, false);
}

int32_t TimerManager::DestroyTimer(uint64_t timerId)
{
    return StopTimerInner(timerId, true);
}

int32_t TimerManager::StopTimerInner(uint64_t timerNumber, bool needDestroy)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "id: %{public}" PRId64 ", needDestroy: %{public}d", timerNumber, needDestroy);
    int32_t ret;
    bool needRecover;
    std::string name = "";
    {
        std::lock_guard<std::mutex> lock(entryMapMutex_);
        ret = StopTimerInnerLocked(needDestroy, timerNumber, needRecover);
    }
    UpdateOrDeleteDatabase(needDestroy, timerNumber, needRecover);
    return ret;
}

// needs to acquire the lock `entryMapMutex_` before calling this method
int32_t TimerManager::StopTimerInnerLocked(bool needDestroy, uint64_t timerNumber, bool &needRecover)
{
    auto it = timerEntryMap_.find(timerNumber);
    if (it == timerEntryMap_.end()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "timer not exist");
        return E_TIME_DEAL_FAILED;
    }
    RemoveHandler(timerNumber);
    TimerProxy::GetInstance().RemoveProxy(timerNumber, it->second->uid);
    TimerProxy::GetInstance().RemovePidProxy(timerNumber, it->second->pid);
    TimerProxy::GetInstance().EraseTimerFromProxyUidMap(timerNumber, it->second->uid);
    TimerProxy::GetInstance().EraseTimerFromProxyPidMap(timerNumber, it->second->pid);
    needRecover = CheckNeedRecoverOnReboot(it->second->bundleName, it->second->type, it->second->autoRestore);
    if (needDestroy) {
        auto uid = it->second->uid;
        auto name = it->second->name;
        timerEntryMap_.erase(it);
        DecreaseTimerCount(uid);
        if (name != "") {
            DeleteTimerName(uid, name, timerNumber);
        }
    }
    return E_TIME_OK;
}

void TimerManager::UpdateOrDeleteDatabase(bool needDestroy, uint64_t timerNumber, bool needRecover)
{
    if (needRecover) {
        if (needDestroy) {
            CjsonHelper::GetInstance().Delete(HOLD_ON_REBOOT, static_cast<int64_t>(timerNumber));
        } else {
            CjsonHelper::GetInstance().UpdateState(HOLD_ON_REBOOT, static_cast<int64_t>(timerNumber));
        }
    } else {
        if (needDestroy) {
            CjsonHelper::GetInstance().Delete(DROP_ON_REBOOT, static_cast<int64_t>(timerNumber));
        } else {
            CjsonHelper::GetInstance().UpdateState(DROP_ON_REBOOT, static_cast<int64_t>(timerNumber));
        }
    }
}

void TimerManager::SetHandler(std::string name,
                              uint64_t id,
                              int type,
                              uint64_t triggerAtTime,
                              int64_t windowLength,
                              uint64_t interval,
                              int flag,
                              bool autoRestore,
                              std::function<int32_t (const uint64_t)> callback,
                              std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                              int uid,
                              int pid,
                              const std::string &bundleName)
{
    auto windowLengthDuration = milliseconds(windowLength);
    if (windowLengthDuration > INTERVAL_HALF_DAY) {
        windowLengthDuration = INTERVAL_HOUR;
    }
    auto intervalDuration = milliseconds(interval > MAX_MILLISECOND ? MAX_MILLISECOND : interval);
    if (intervalDuration > milliseconds::zero() && intervalDuration < MIN_INTERVAL_ONE_SECONDS) {
        intervalDuration = MIN_INTERVAL_ONE_SECONDS;
    } else if (intervalDuration > MAX_INTERVAL) {
        intervalDuration = MAX_INTERVAL;
    }

    auto nowElapsed = GetBootTimeNs();
    auto when = milliseconds(triggerAtTime > MAX_MILLISECOND ? MAX_MILLISECOND : triggerAtTime);
    auto nominalTrigger = ConvertToElapsed(when, type);
    auto minTrigger = nowElapsed + ZERO_FUTURITY;
    auto triggerElapsed = (nominalTrigger > minTrigger) ? nominalTrigger : minTrigger;

    steady_clock::time_point maxElapsed;
    if (windowLengthDuration == milliseconds::zero()) {
        maxElapsed = triggerElapsed;
    } else if (windowLengthDuration < milliseconds::zero()) {
        maxElapsed = MaxTriggerTime(nominalTrigger, triggerElapsed, intervalDuration);
        windowLengthDuration = duration_cast<milliseconds>(maxElapsed - triggerElapsed);
    } else {
        maxElapsed = triggerElapsed + windowLengthDuration;
    }
    std::lock_guard<std::mutex> lockGuard(mutex_);
    SetHandlerLocked(name,
                     id,
                     type,
                     when,
                     triggerElapsed,
                     windowLengthDuration,
                     maxElapsed,
                     intervalDuration,
                     std::move(callback),
                     wantAgent,
                     static_cast<uint32_t>(flag),
                     autoRestore,
                     uid,
                     pid,
                     bundleName);
}

void TimerManager::SetHandlerLocked(std::string name, uint64_t id, int type,
                                    std::chrono::milliseconds when,
                                    std::chrono::steady_clock::time_point whenElapsed,
                                    std::chrono::milliseconds windowLength,
                                    std::chrono::steady_clock::time_point maxWhen,
                                    std::chrono::milliseconds interval,
                                    std::function<int32_t (const uint64_t)> callback,
                                    const std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> &wantAgent,
                                    uint32_t flags,
                                    bool autoRestore,
                                    uint64_t callingUid,
                                    uint64_t callingPid,
                                    const std::string &bundleName)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start id: %{public}" PRId64 "", id);
    auto alarm = std::make_shared<TimerInfo>(name, id, type, when, whenElapsed, windowLength, maxWhen,
                                             interval, std::move(callback), wantAgent, flags, autoRestore, callingUid,
                                             callingPid, bundleName);
    if (TimerProxy::GetInstance().IsUidProxy(alarm->uid)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Timer already proxy, uid=%{public}" PRIu64 " id=%{public}" PRId64 "",
            callingUid, alarm->id);
        TimerProxy::GetInstance().RecordProxyUidTimerMap(alarm);
        alarm->UpdateWhenElapsedFromNow(GetBootTimeNs(), milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
    }
    if (TimerProxy::GetInstance().IsPidProxy(alarm->pid)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Timer already proxy, pid=%{public}" PRIu64 " id=%{public}" PRId64 "",
            callingPid, alarm->id);
        TimerProxy::GetInstance().RecordProxyPidTimerMap(alarm);
        alarm->UpdateWhenElapsedFromNow(GetBootTimeNs(), milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
    }
    
    SetHandlerLocked(alarm, false, false);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
}

void TimerManager::RemoveHandler(uint64_t id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RemoveLocked(id, true);
    TimerProxy::GetInstance().RemoveUidTimerMap(id);
    TimerProxy::GetInstance().RemovePidTimerMap(id);
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::RemoveLocked(uint64_t id, bool needReschedule)
{
    auto whichAlarms = [id](const TimerInfo &timer) {
        return timer.id == id;
    };

    bool didRemove = false;
    for (auto it = alarmBatches_.begin(); it != alarmBatches_.end();) {
        auto batch = *it;
        didRemove = batch->Remove(whichAlarms);
        if (didRemove) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "remove id: %{public}" PRIu64 "", id);
            it = alarmBatches_.erase(it);
            if (batch->Size() != 0) {
                TIME_HILOGI(TIME_MODULE_SERVICE, "reorder batch");
                AddBatchLocked(alarmBatches_, batch);
            }
            break;
        }
        ++it;
    }
    pendingDelayTimers_.erase(remove_if(pendingDelayTimers_.begin(), pendingDelayTimers_.end(),
        [id](const std::shared_ptr<TimerInfo> &timer) {
            return timer->id == id;
        }), pendingDelayTimers_.end());
    delayedTimers_.erase(id);
    if (mPendingIdleUntil_ != nullptr && id == mPendingIdleUntil_->id) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Idle alarm removed.");
        mPendingIdleUntil_ = nullptr;
        bool isAdjust = AdjustTimersBasedOnDeviceIdle();
        delayedTimers_.clear();
        for (const auto &pendingTimer : pendingDelayTimers_) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Set timer from delay list, id=%{public}" PRId64 "", pendingTimer->id);
            if (pendingTimer->whenElapsed <= GetBootTimeNs()) {
                // 2 means the time of performing task.
                pendingTimer->UpdateWhenElapsedFromNow(GetBootTimeNs(), milliseconds(2));
            } else {
                pendingTimer->UpdateWhenElapsedFromNow(GetBootTimeNs(), pendingTimer->offset);
            }
            SetHandlerLocked(pendingTimer, false, false);
        }
        pendingDelayTimers_.clear();
        if (isAdjust) {
            ReBatchAllTimers();
            return;
        }
    }

    if (needReschedule && didRemove) {
        RescheduleKernelTimerLocked();
    }
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::SetHandlerLocked(std::shared_ptr<TimerInfo> alarm, bool rebatching, bool isRebatched)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start rebatching= %{public}d", rebatching);
    TimerProxy::GetInstance().RecordUidTimerMap(alarm, isRebatched);
    TimerProxy::GetInstance().RecordPidTimerMap(alarm, isRebatched);

    if (!isRebatched && mPendingIdleUntil_ != nullptr && !CheckAllowWhileIdle(alarm)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Pending not-allowed alarm in idle state, id=%{public}" PRId64 "",
            alarm->id);
        alarm->offset = duration_cast<milliseconds>(alarm->whenElapsed - GetBootTimeNs());
        pendingDelayTimers_.push_back(alarm);
        return;
    }
    if (!rebatching) {
        AdjustSingleTimer(alarm);
    }
    bool isAdjust = false;
    if (!isRebatched && alarm->flags & static_cast<uint32_t>(IDLE_UNTIL)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Set idle timer, id=%{public}" PRId64 "", alarm->id);
        mPendingIdleUntil_ = alarm;
        isAdjust = AdjustTimersBasedOnDeviceIdle();
    }
    InsertAndBatchTimerLocked(std::move(alarm));
    if (isAdjust) {
        ReBatchAllTimers();
        rebatching = true;
    }
    if (!rebatching) {
        RescheduleKernelTimerLocked();
    }
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::ReBatchAllTimers()
{
    auto oldSet = alarmBatches_;
    alarmBatches_.clear();
    auto nowElapsed = GetBootTimeNs();
    for (const auto &batch : oldSet) {
        auto n = batch->Size();
        for (unsigned int i = 0; i < n; i++) {
            ReAddTimerLocked(batch->Get(i), nowElapsed);
        }
    }
    RescheduleKernelTimerLocked();
}

void TimerManager::ReAddTimerLocked(std::shared_ptr<TimerInfo> timer,
                                    std::chrono::steady_clock::time_point nowElapsed)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "ReAddTimerLocked start. uid= %{public}d, id=%{public}" PRId64 ""
        ", timer originMaxWhenElapsed=%{public}lld, whenElapsed=%{public}lld, now=%{public}lld",
        timer->uid, timer->id, timer->originWhenElapsed.time_since_epoch().count(),
        timer->whenElapsed.time_since_epoch().count(), GetBootTimeNs().time_since_epoch().count());
    auto whenElapsed = ConvertToElapsed(timer->when, timer->type);
    steady_clock::time_point maxElapsed;
    if (timer->windowLength == milliseconds::zero()) {
        maxElapsed = whenElapsed;
    } else {
        maxElapsed = (timer->windowLength > milliseconds::zero()) ?
                     (whenElapsed + timer->windowLength) :
                     MaxTriggerTime(nowElapsed, whenElapsed, timer->repeatInterval);
    }
    timer->whenElapsed = whenElapsed;
    timer->maxWhenElapsed = maxElapsed;
    SetHandlerLocked(timer, true, true);
}

std::chrono::steady_clock::time_point TimerManager::ConvertToElapsed(std::chrono::milliseconds when, int type)
{
    auto bootTimePoint = GetBootTimeNs();
    if (type == RTC || type == RTC_WAKEUP) {
        auto systemTimeNow = system_clock::now().time_since_epoch();
        auto offset = when - systemTimeNow;
        TIME_HILOGD(TIME_MODULE_SERVICE, "systemTimeNow : %{public}lld offset : %{public}lld",
                    systemTimeNow.count(), offset.count());
        if (offset.count() <= 0) {
            return bootTimePoint;
        } else {
            return bootTimePoint + offset;
        }
    }
    auto bootTimeNow = bootTimePoint.time_since_epoch();
    auto offset = when - bootTimeNow;
    TIME_HILOGD(TIME_MODULE_SERVICE, "bootTimeNow : %{public}lld offset : %{public}lld",
                bootTimeNow.count(), offset.count());
    if (offset.count() <= 0) {
        return bootTimePoint;
    } else {
        return bootTimePoint + offset;
    }
}

void TimerManager::TimerLooper()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Start timer wait loop");
    pthread_setname_np(pthread_self(), "timer_loop");
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    while (runFlag_) {
        uint32_t result = handler_->WaitForAlarm();
        auto nowRtc = std::chrono::system_clock::now();
        auto nowElapsed = GetBootTimeNs();
        triggerList.clear();

        if ((result & TIME_CHANGED_MASK) != 0) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "ret: %{public}u", result);
            system_clock::time_point lastTimeChangeClockTime;
            system_clock::time_point expectedClockTime;
            std::lock_guard<std::mutex> lock(mutex_);
            lastTimeChangeClockTime = lastTimeChangeClockTime_;
            expectedClockTime = lastTimeChangeClockTime +
                (duration_cast<milliseconds>(nowElapsed.time_since_epoch()) -
                duration_cast<milliseconds>(lastTimeChangeRealtime_.time_since_epoch()));
            if (lastTimeChangeClockTime == system_clock::time_point::min()
                || nowRtc < expectedClockTime
                || nowRtc > (expectedClockTime + milliseconds(ONE_THOUSAND))) {
                ReBatchAllTimers();
                lastTimeChangeClockTime_ = nowRtc;
                lastTimeChangeRealtime_ = nowElapsed;
            }
        }

        if (result != TIME_CHANGED_MASK) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                TriggerTimersLocked(triggerList, nowElapsed);
            }
            // in this function, timeservice apply a runninglock from powermanager
            // release mutex to prevent powermanager from using the interface of timeservice
            // which may cause deadlock
            DeliverTimersLocked(triggerList);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                RescheduleKernelTimerLocked();
            }
        }
    }
}

TimerManager::~TimerManager()
{
    if (alarmThread_ && alarmThread_->joinable()) {
        runFlag_ = false;
        alarmThread_->join();
    }
}

steady_clock::time_point TimerManager::GetBootTimeNs()
{
    int64_t timeNow = -1;
    struct timespec tv {};
    if (clock_gettime(CLOCK_BOOTTIME, &tv) < 0) {
        return steady_clock::now();
    }
    timeNow = tv.tv_sec * NANO_TO_SECOND + tv.tv_nsec;
    steady_clock::time_point tp_epoch ((nanoseconds(timeNow)));
    return tp_epoch;
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::TriggerIdleTimer()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Idle alarm triggers.");
    mPendingIdleUntil_ = nullptr;
    delayedTimers_.clear();
    std::for_each(pendingDelayTimers_.begin(), pendingDelayTimers_.end(),
        [this](const std::shared_ptr<TimerInfo> &pendingTimer) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Set timer from delay list, id=%{public}" PRId64 "", pendingTimer->id);
            if (pendingTimer->whenElapsed > GetBootTimeNs()) {
                pendingTimer->UpdateWhenElapsedFromNow(GetBootTimeNs(), pendingTimer->offset);
            } else {
                // 2 means the time of performing task.
                pendingTimer->UpdateWhenElapsedFromNow(GetBootTimeNs(), milliseconds(2));
            }
            SetHandlerLocked(pendingTimer, false, false);
        });
    pendingDelayTimers_.clear();
    ReBatchAllTimers();
}

// needs to acquire the lock `mutex_` before calling this method
bool TimerManager::ProcTriggerTimer(std::shared_ptr<TimerInfo> &alarm,
                                    const std::chrono::steady_clock::time_point &nowElapsed)
{
    if (mPendingIdleUntil_ != nullptr && mPendingIdleUntil_->id == alarm->id) {
        TriggerIdleTimer();
    }
    if (TimerProxy::GetInstance().IsUidProxy(alarm->uid)) {
        alarm->UpdateWhenElapsedFromNow(nowElapsed, milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
        TIME_HILOGD(TIME_MODULE_SERVICE, "UpdateWhenElapsed for proxy timer trigger. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            alarm->uid, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
            nowElapsed.time_since_epoch().count());
        SetHandlerLocked(alarm, false, false);
        return false;
    } else if (TimerProxy::GetInstance().IsPidProxy(alarm->pid)) {
        alarm->UpdateWhenElapsedFromNow(nowElapsed, milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
        TIME_HILOGD(TIME_MODULE_SERVICE, "UpdateWhenElapsed for proxy timer trigger. "
            "pid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            alarm->pid, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
            nowElapsed.time_since_epoch().count());
        SetHandlerLocked(alarm, false, false);
        return false;
    } else {
        HandleRepeatTimer(alarm, nowElapsed);
        return true;
    }
}

// needs to acquire the lock `mutex_` before calling this method
bool TimerManager::TriggerTimersLocked(std::vector<std::shared_ptr<TimerInfo>> &triggerList,
                                       std::chrono::steady_clock::time_point nowElapsed)
{
    bool hasWakeup = false;
    TIME_HILOGD(TIME_MODULE_SERVICE, "current time %{public}lld", GetBootTimeNs().time_since_epoch().count());

    for (auto iter = alarmBatches_.begin(); iter != alarmBatches_.end();) {
        if (*iter == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "alarmBatches_ has nullptr");
            iter = alarmBatches_.erase(iter);
            continue;
        }
        if ((*iter)->GetStart() > nowElapsed) {
            ++iter;
            continue;
        }
        auto batch = *iter;
        iter = alarmBatches_.erase(iter);
        TIME_HILOGD(
            TIME_MODULE_SERVICE, "batch size= %{public}d", static_cast<int>(alarmBatches_.size()));
        const auto n = batch->Size();
        for (unsigned int i = 0; i < n; ++i) {
            auto alarm = batch->Get(i);
            triggerList.push_back(alarm);
            TIME_SIMPLIFY_HILOGI(TIME_MODULE_SERVICE, "uid: %{public}d id:%{public}" PRId64 " name:%{public}s"
                " wk:%{public}u",
                alarm->uid, alarm->id, alarm->bundleName.c_str(), alarm->wakeup);

            if (alarm->wakeup) {
                hasWakeup = true;
            }
        }
    }
    for (auto iter = triggerList.begin(); iter != triggerList.end();) {
        auto alarm = *iter;
        if (!ProcTriggerTimer(alarm, nowElapsed)) {
            iter = triggerList.erase(iter);
        } else {
            ++iter;
        }
    }

    std::sort(triggerList.begin(), triggerList.end(),
        [](const std::shared_ptr<TimerInfo> &l, const std::shared_ptr<TimerInfo> &r) {
            return l->whenElapsed < r->whenElapsed;
        });

    return hasWakeup;
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::RescheduleKernelTimerLocked()
{
    auto bootTime = GetBootTimeNs();
    if (!alarmBatches_.empty()) {
        auto firstWakeup = FindFirstWakeupBatchLocked();
        auto firstBatch = alarmBatches_.front();
        if (firstWakeup != nullptr) {
            #ifdef POWER_MANAGER_ENABLE
            HandleRunningLock(firstWakeup);
            #endif
            auto setTimePoint = firstWakeup->GetStart().time_since_epoch();
            if (setTimePoint.count() != lastSetTime_[ELAPSED_REALTIME_WAKEUP]) {
                SetLocked(ELAPSED_REALTIME_WAKEUP, setTimePoint, bootTime);
                lastSetTime_[ELAPSED_REALTIME_WAKEUP] = setTimePoint.count();
            }
        }
        if (firstBatch != firstWakeup) {
            auto setTimePoint = firstBatch->GetStart().time_since_epoch();
            if (setTimePoint.count() != lastSetTime_[ELAPSED_REALTIME]) {
                SetLocked(ELAPSED_REALTIME, setTimePoint, bootTime);
                lastSetTime_[ELAPSED_REALTIME] = setTimePoint.count();
            }
        }
    }
}

// needs to acquire the lock `mutex_` before calling this method
std::shared_ptr<Batch> TimerManager::FindFirstWakeupBatchLocked()
{
    auto it = std::find_if(alarmBatches_.begin(),
                           alarmBatches_.end(),
                           [](const std::shared_ptr<Batch> &batch) {
                               return batch->HasWakeups();
                           });
    return (it != alarmBatches_.end()) ? *it : nullptr;
}

void TimerManager::SetLocked(int type, std::chrono::nanoseconds when, std::chrono::steady_clock::time_point bootTime)
{
    handler_->Set(static_cast<uint32_t>(type), when, bootTime);
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::InsertAndBatchTimerLocked(std::shared_ptr<TimerInfo> alarm)
{
    int64_t whichBatch = (alarm->flags & static_cast<uint32_t>(STANDALONE)) ?
                         -1 :
                         AttemptCoalesceLocked(alarm->whenElapsed, alarm->maxWhenElapsed);
    TIME_SIMPLIFY_HILOGI(TIME_MODULE_SERVICE, "bat: %{public}" PRId64 " id:%{public}" PRIu64 " "
                         "we:%{public}lld mwe:%{public}lld",
                         whichBatch, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
                         alarm->maxWhenElapsed.time_since_epoch().count());
    if (whichBatch < 0) {
        AddBatchLocked(alarmBatches_, std::make_shared<Batch>(*alarm));
    } else {
        auto batch = alarmBatches_.at(whichBatch);
        if (batch->Add(alarm)) {
            alarmBatches_.erase(alarmBatches_.begin() + whichBatch);
            AddBatchLocked(alarmBatches_, batch);
        }
    }
}

// needs to acquire the lock `mutex_` before calling this method
int64_t TimerManager::AttemptCoalesceLocked(std::chrono::steady_clock::time_point whenElapsed,
                                            std::chrono::steady_clock::time_point maxWhen)
{
    auto it = std::find_if(alarmBatches_.begin(), alarmBatches_.end(),
        [whenElapsed, maxWhen](const std::shared_ptr<Batch> &batch) {
            return (batch->GetFlags() & static_cast<uint32_t>(STANDALONE)) == 0 &&
                   (batch->CanHold(whenElapsed, maxWhen));
        });
    if (it != alarmBatches_.end()) {
        return std::distance(alarmBatches_.begin(), it);
    }
    return -1;
}

void TimerManager::NotifyWantAgentRetry(std::shared_ptr<TimerInfo> timer)
{
    auto retryRegister = [timer]() {
        for (int i = 0; i < WANT_RETRY_TIMES; i++) {
            sleep(WANT_RETRY_INTERVAL << i);
            if (TimerManager::GetInstance()->NotifyWantAgent(timer)) {
                return;
            }
        }
    };
    std::thread thread(retryRegister);
    thread.detach();
}

int32_t TimerManager::CheckUserIdForNotify(const std::shared_ptr<TimerInfo> &timer)
{
    auto bundleList = TimeFileUtils::GetBundleList();
    if (!bundleList.empty() && timer->bundleName == bundleList[0]) {
        return E_TIME_OK;
    }
    int userIdOfTimer = -1;
    int foregroundUserId = -1;
    int getLocalIdErr = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(timer->uid, userIdOfTimer);
    if (getLocalIdErr != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Get account id from uid failed, errcode: %{public}d", getLocalIdErr);
        return E_TIME_ACCOUNT_ERROR;
    }
    int getForegroundIdErr = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(foregroundUserId);
    if (getForegroundIdErr != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Get foreground account id failed, errcode: %{public}d", getForegroundIdErr);
        return E_TIME_ACCOUNT_ERROR;
    }
    if (userIdOfTimer == foregroundUserId || userIdOfTimer == SYSTEM_USER_ID) {
        return E_TIME_OK;
    } else {
        TIME_HILOGI(TIME_MODULE_SERVICE, "WA wait switch user, uid: %{public}d, timerId: %{public}" PRId64,
            timer->uid, timer->id);
        return E_TIME_ACCOUNT_NOT_MATCH;
    }
}

void TimerManager::DeliverTimersLocked(const std::vector<std::shared_ptr<TimerInfo>> &triggerList)
{
    auto wakeupNums = std::count_if(triggerList.begin(), triggerList.end(), [](auto timer) {return timer->wakeup;});
    for (const auto &timer : triggerList) {
        if (timer->wakeup) {
            #ifdef POWER_MANAGER_ENABLE
            TIME_HILOGD(TIME_MODULE_SERVICE, "id: %{public}" PRId64 ", uid: %{public}d bundleName: %{public}s",
                        timer->id, timer->uid, timer->bundleName.c_str());
            AddRunningLock(USE_LOCK_ONE_SEC_IN_NANO);
            #endif
            StatisticReporter(IPCSkeleton::GetCallingPid(), wakeupNums, timer);
        }
        if (timer->callback) {
            if (TimerProxy::GetInstance().CallbackAlarmIfNeed(timer) == PEER_END_DEAD
                && !timer->wantAgent) {
                DestroyTimer(timer->id);
                continue;
            }
        }
        if (timer->wantAgent) {
            if (!NotifyWantAgent(timer) &&
                CheckNeedRecoverOnReboot(timer->bundleName, timer->type, timer->autoRestore)) {
                NotifyWantAgentRetry(timer);
            }
            if (CheckNeedRecoverOnReboot(timer->bundleName, timer->type, timer->autoRestore)) {
                CjsonHelper::GetInstance().UpdateState(HOLD_ON_REBOOT, static_cast<int64_t>(timer->id));
            } else {
                CjsonHelper::GetInstance().UpdateState(DROP_ON_REBOOT, static_cast<int64_t>(timer->id));
            }
        }
        if (((timer->flags & static_cast<uint32_t>(IS_DISPOSABLE)) > 0) &&
            (timer->repeatInterval == milliseconds::zero())) {
            DestroyTimer(timer->id);
        }
    }
}

bool TimerManager::NotifyWantAgent(const std::shared_ptr<TimerInfo> &timer)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "trigger wantAgent.");
    auto wantAgent = timer->wantAgent;
    std::shared_ptr<AAFwk::Want> want = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
    if (want == nullptr) {
        switch (CheckUserIdForNotify(timer)) {
            case E_TIME_ACCOUNT_NOT_MATCH:
                // No need to retry.
                return true;
            case E_TIME_ACCOUNT_ERROR:
                TIME_HILOGE(TIME_MODULE_SERVICE, "want is nullptr, id=%{public}" PRId64 "", timer->id);
                return false;
            default:
                break;
        }
        auto wantStr = CjsonHelper::GetInstance().QueryWant(HOLD_ON_REBOOT, timer->id);
        if (wantStr == "") {
            TIME_HILOGE(TIME_MODULE_SERVICE, "db query failed");
            return false;
        }
        wantAgent = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::FromString(wantStr);
        switch (CheckUserIdForNotify(timer)) {
            case E_TIME_ACCOUNT_NOT_MATCH:
                TIME_HILOGI(TIME_MODULE_SERVICE, "user sw after FS, id=%{public}" PRId64 "", timer->id);
                // No need to retry.
                return true;
            case E_TIME_ACCOUNT_ERROR:
                TIME_HILOGE(TIME_MODULE_SERVICE, "want is nullptr, id=%{public}" PRId64 "", timer->id);
                return false;
            default:
                break;
        }
        want = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
        if (want == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "want is nullptr, id=%{public}" PRId64 "", timer->id);
            return false;
        }
    }
    OHOS::AbilityRuntime::WantAgent::TriggerInfo paramsInfo("", nullptr, want, WANTAGENT_CODE_ELEVEN);
    auto code = AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(wantAgent, nullptr, paramsInfo);
    TIME_SIMPLIFY_HILOGI(TIME_MODULE_SERVICE, "trigWA ret: %{public}d", code);
    return code == ERR_OK;
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::UpdateTimersState(std::shared_ptr<TimerInfo> &alarm)
{
    RemoveLocked(alarm->id, false);
    AdjustSingleTimer(alarm);
    InsertAndBatchTimerLocked(alarm);
    RescheduleKernelTimerLocked();
}

bool TimerManager::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TimerProxy::GetInstance().ProxyTimer(uid, isProxy, needRetrigger, GetBootTimeNs(),
        [this] (std::shared_ptr<TimerInfo> &alarm) { UpdateTimersState(alarm); });
}

bool TimerManager::AdjustTimer(bool isAdjust, uint32_t interval)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (adjustPolicy_ == isAdjust && adjustInterval_ == interval) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "already deal timer adjust, flag: %{public}d", isAdjust);
        return false;
    }
    std::chrono::steady_clock::time_point now = GetBootTimeNs();
    adjustPolicy_ = isAdjust;
    adjustInterval_ = interval;
    auto callback = [this] (AdjustTimerCallback adjustTimer) {
        bool isChanged = false;
        auto nowElapsed = GetBootTimeNs();
        for (const auto &batch : alarmBatches_) {
            if (!batch) {
                continue;
            }
            auto n = batch->Size();
            for (unsigned int i = 0; i < n; i++) {
                auto timer = batch->Get(i);
                ReCalcuOriWhenElapsed(timer, nowElapsed);
                isChanged = adjustTimer(timer) || isChanged;
            }
        }
        if (isChanged) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "timer adjust executing, policy: %{public}d", adjustPolicy_);
            ReBatchAllTimers();
        }
    };

    return TimerProxy::GetInstance().AdjustTimer(isAdjust, interval, now, callback);
}

bool TimerManager::ProxyTimer(int32_t uid, std::set<int> pidList, bool isProxy, bool needRetrigger)
{
    std::set<int> failurePid;
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::set<int>::iterator pid = pidList.begin(); pid != pidList.end(); ++pid) {
        if (!TimerProxy::GetInstance().PidProxyTimer(uid, *pid, isProxy, needRetrigger, GetBootTimeNs(),
            [this] (std::shared_ptr<TimerInfo> &alarm) { UpdateTimersState(alarm); })) {
            failurePid.insert(*pid);
        }
    }
    return (failurePid.size() == 0);
}

void TimerManager::ReCalcuOriWhenElapsed(std::shared_ptr<TimerInfo> timer,
                                         std::chrono::steady_clock::time_point nowElapsed)
{
    if (adjustPolicy_) {
        return;
    }
    auto whenElapsed = ConvertToElapsed(timer->origWhen, timer->type);
    steady_clock::time_point maxElapsed;
    if (timer->windowLength == milliseconds::zero()) {
        maxElapsed = whenElapsed;
    } else {
        maxElapsed = (timer->windowLength > milliseconds::zero()) ?
                     (whenElapsed + timer->windowLength) :
                     MaxTriggerTime(nowElapsed, whenElapsed, timer->repeatInterval);
    }
    timer->originWhenElapsed = whenElapsed;
    timer->originMaxWhenElapsed = maxElapsed;
}

void TimerManager::SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption)
{
    std::lock_guard<std::mutex> lock(mutex_);
    TimerProxy::GetInstance().SetTimerExemption(nameArr, isExemption);
}

bool TimerManager::AdjustSingleTimer(std::shared_ptr<TimerInfo> timer)
{
    if (!adjustPolicy_) {
        return false;
    }
    return TimerProxy::GetInstance().AdjustTimer(adjustPolicy_, adjustInterval_, GetBootTimeNs(),
        [this, timer] (AdjustTimerCallback adjustTimer) { adjustTimer(timer); });
}

bool TimerManager::ResetAllProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TimerProxy::GetInstance().ResetAllProxy(GetBootTimeNs(),
        [this] (std::shared_ptr<TimerInfo> &alarm) { UpdateTimersState(alarm); });
}

bool TimerManager::CheckAllowWhileIdle(const std::shared_ptr<TimerInfo> &alarm)
{
#ifdef DEVICE_STANDBY_ENABLE
    if (TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
        std::vector<DevStandbyMgr::AllowInfo> restrictList;
        DevStandbyMgr::StandbyServiceClient::GetInstance().GetRestrictList(DevStandbyMgr::AllowType::TIMER,
            restrictList, REASON_APP_API);
        auto it = std::find_if(restrictList.begin(), restrictList.end(),
            [&alarm](const DevStandbyMgr::AllowInfo &allowInfo) { return allowInfo.GetName() == alarm->bundleName; });
        if (it != restrictList.end()) {
            return false;
        }
    }

    if (TimePermission::CheckProxyCallingPermission()) {
        pid_t pid = IPCSkeleton::GetCallingPid();
        std::string procName = TimeFileUtils::GetNameByPid(pid);
        if (alarm->flags & static_cast<uint32_t>(INEXACT_REMINDER)) {
            return false;
        }
        std::vector<DevStandbyMgr::AllowInfo> restrictList;
        DevStandbyMgr::StandbyServiceClient::GetInstance().GetRestrictList(DevStandbyMgr::AllowType::TIMER,
            restrictList, REASON_NATIVE_API);
        auto it = std::find_if(restrictList.begin(), restrictList.end(),
            [procName](const DevStandbyMgr::AllowInfo &allowInfo) { return allowInfo.GetName() == procName; });
        if (it != restrictList.end()) {
            return false;
        }
    }
#endif
    return true;
}

// needs to acquire the lock `mutex_` before calling this method
bool TimerManager::AdjustDeliveryTimeBasedOnDeviceIdle(const std::shared_ptr<TimerInfo> &alarm)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start adjust timer, uid=%{public}d, id=%{public}" PRId64 "",
        alarm->uid, alarm->id);
    if (mPendingIdleUntil_ == alarm) {
        return false;
    }
    if (mPendingIdleUntil_ == nullptr) {
        auto itMap = delayedTimers_.find(alarm->id);
        if (itMap != delayedTimers_.end()) {
            std::chrono::milliseconds currentTime;
            if (alarm->type == RTC || alarm->type == RTC_WAKEUP) {
                currentTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
            } else {
                currentTime = duration_cast<milliseconds>(GetBootTimeNs().time_since_epoch());
            }

            if (alarm->origWhen > currentTime) {
                auto offset = alarm->origWhen - currentTime;
                return alarm->UpdateWhenElapsedFromNow(GetBootTimeNs(), offset);
            }
            // 2 means the time of performing task.
            return alarm->UpdateWhenElapsedFromNow(GetBootTimeNs(), milliseconds(2));
        }
        return false;
    }

    if (CheckAllowWhileIdle(alarm)) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Timer unrestricted, not adjust. id=%{public}" PRId64 "", alarm->id);
        return false;
    } else if (alarm->whenElapsed > mPendingIdleUntil_->whenElapsed) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Timer not allowed, not adjust. id=%{public}" PRId64 "", alarm->id);
        return false;
    } else {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Timer not allowed, id=%{public}" PRId64 "", alarm->id);
        delayedTimers_[alarm->id] = alarm->whenElapsed;
        auto offset = ConvertToElapsed(mPendingIdleUntil_->when, mPendingIdleUntil_->type) - GetBootTimeNs();
        return alarm->UpdateWhenElapsedFromNow(GetBootTimeNs(), offset);
    }
}

// needs to acquire the lock `mutex_` before calling this method
bool TimerManager::AdjustTimersBasedOnDeviceIdle()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start adjust alarmBatches_.size=%{public}d",
        static_cast<int>(alarmBatches_.size()));
    bool isAdjust = false;
    for (const auto &batch : alarmBatches_) {
        auto n = batch->Size();
        for (unsigned int i = 0; i < n; i++) {
            auto alarm = batch->Get(i);
            isAdjust = AdjustDeliveryTimeBasedOnDeviceIdle(alarm) || isAdjust;
        }
    }
    return isAdjust;
}

// needs to acquire the lock `mutex_` before calling this method
bool AddBatchLocked(std::vector<std::shared_ptr<Batch>> &list, const std::shared_ptr<Batch> &newBatch)
{
    auto it = std::upper_bound(list.begin(),
                               list.end(),
                               newBatch,
                               [](const std::shared_ptr<Batch> &first, const std::shared_ptr<Batch> &second) {
                                   return first->GetStart() < second->GetStart();
                               });
    list.insert(it, newBatch);
    return it == list.begin();
}

steady_clock::time_point MaxTriggerTime(steady_clock::time_point now,
                                        steady_clock::time_point triggerAtTime,
                                        milliseconds interval)
{
    milliseconds futurity = (interval == milliseconds::zero()) ?
                            (duration_cast<milliseconds>(triggerAtTime - now)) : interval;
    if (futurity < MIN_FUZZABLE_INTERVAL) {
        futurity = milliseconds::zero();
    }
    return triggerAtTime + milliseconds(static_cast<long>(BATCH_WINDOW_COE * futurity.count()));
}

bool TimerManager::ShowTimerEntryMap(int fd)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    auto iter = timerEntryMap_.begin();
    for (; iter != timerEntryMap_.end(); iter++) {
        dprintf(fd, " - dump timer number   = %lu\n", iter->first);
        dprintf(fd, " * timer name          = %s\n", iter->second->name.c_str());
        dprintf(fd, " * timer id            = %lu\n", iter->second->id);
        dprintf(fd, " * timer type          = %d\n", iter->second->type);
        dprintf(fd, " * timer flag          = %lu\n", iter->second->flag);
        dprintf(fd, " * timer window Length = %lld\n", iter->second->windowLength);
        dprintf(fd, " * timer interval      = %lu\n", iter->second->interval);
        dprintf(fd, " * timer uid           = %d\n\n", iter->second->uid);
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerManager::ShowTimerEntryById(int fd, uint64_t timerId)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    auto iter = timerEntryMap_.find(timerId);
    if (iter == timerEntryMap_.end()) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
        return false;
    } else {
        dprintf(fd, " - dump timer number   = %lu\n", iter->first);
        dprintf(fd, " * timer id            = %lu\n", iter->second->id);
        dprintf(fd, " * timer type          = %d\n", iter->second->type);
        dprintf(fd, " * timer window Length = %lld\n", iter->second->windowLength);
        dprintf(fd, " * timer interval      = %lu\n", iter->second->interval);
        dprintf(fd, " * timer uid           = %d\n\n", iter->second->uid);
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerManager::ShowTimerTriggerById(int fd, uint64_t timerId)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < alarmBatches_.size(); i++) {
        for (size_t j = 0; j < alarmBatches_[i]->Size(); j++) {
            if (alarmBatches_[i]->Get(j)->id == timerId) {
                dprintf(fd, " - dump timer id   = %lu\n", alarmBatches_[i]->Get(j)->id);
                dprintf(fd, " * timer trigger   = %lld\n", alarmBatches_[i]->Get(j)->origWhen);
            }
        }
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerManager::ShowIdleTimerInfo(int fd)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lock(mutex_);
    dprintf(fd, " - dump idle state         = %d\n", (mPendingIdleUntil_ != nullptr));
    if (mPendingIdleUntil_ != nullptr) {
        dprintf(fd, " - dump idle timer id  = %lu\n", mPendingIdleUntil_->id);
        dprintf(fd, " * timer type          = %d\n", mPendingIdleUntil_->type);
        dprintf(fd, " * timer flag          = %lu\n", mPendingIdleUntil_->flags);
        dprintf(fd, " * timer window Length = %lu\n", mPendingIdleUntil_->windowLength);
        dprintf(fd, " * timer interval      = %lu\n", mPendingIdleUntil_->repeatInterval);
        dprintf(fd, " * timer whenElapsed   = %lu\n", mPendingIdleUntil_->whenElapsed);
        dprintf(fd, " * timer uid           = %d\n\n", mPendingIdleUntil_->uid);
    }
    for (const auto &pendingTimer : pendingDelayTimers_) {
        dprintf(fd, " - dump pending delay timer id  = %lu\n", pendingTimer->id);
        dprintf(fd, " * timer type          = %d\n", pendingTimer->type);
        dprintf(fd, " * timer flag          = %lu\n", pendingTimer->flags);
        dprintf(fd, " * timer window Length = %lu\n", pendingTimer->windowLength);
        dprintf(fd, " * timer interval      = %lu\n", pendingTimer->repeatInterval);
        dprintf(fd, " * timer whenElapsed   = %lu\n", pendingTimer->whenElapsed);
        dprintf(fd, " * timer uid           = %d\n\n", pendingTimer->uid);
    }
    for (const auto &delayedTimer : delayedTimers_) {
        dprintf(fd, " - dump delayed timer id = %lu\n", delayedTimer.first);
        dprintf(fd, " * timer whenElapsed     = %lu\n", delayedTimer.second);
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

void TimerManager::OnUserRemoved(int userId)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Removed userId: %{public}d", userId);
    std::vector<std::shared_ptr<TimerEntry>> removeList;
    {
        std::lock_guard<std::mutex> lock(entryMapMutex_);
        for (auto it = timerEntryMap_.begin(); it != timerEntryMap_.end(); ++it) {
            int userIdOfTimer = -1;
            AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(it->second->uid, userIdOfTimer);
            if (userId == userIdOfTimer) {
                removeList.push_back(it->second);
            }
        }
    }
    for (auto it = removeList.begin(); it != removeList.end(); ++it) {
        DestroyTimer((*it)->id);
    }
}

void TimerManager::OnPackageRemoved(int uid)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Removed uid: %{public}d", uid);
    std::vector<std::shared_ptr<TimerEntry>> removeList;
    {
        std::lock_guard<std::mutex> lock(entryMapMutex_);
        for (auto it = timerEntryMap_.begin(); it != timerEntryMap_.end(); ++it) {
            if (it->second->uid == uid) {
                removeList.push_back(it->second);
            }
        }
    }
    for (auto it = removeList.begin(); it != removeList.end(); ++it) {
        DestroyTimer((*it)->id);
    }
}

void TimerManager::HandleRSSDeath()
{
    TIME_HILOGI(TIME_MODULE_CLIENT, "RSSSaDeathRecipient died.");
    uint64_t id = 0;
    {
        std::lock_guard <std::mutex> lock(mutex_);
        if (mPendingIdleUntil_ != nullptr) {
            id = mPendingIdleUntil_->id;
        } else {
            return;
        }
    }
    StopTimerInner(id, true);
}

void TimerManager::HandleRepeatTimer(
    const std::shared_ptr<TimerInfo> &timer, std::chrono::steady_clock::time_point nowElapsed)
{
    if (timer->repeatInterval > milliseconds::zero()) {
        uint64_t count = 1 + static_cast<uint64_t>(
            duration_cast<milliseconds>(nowElapsed - timer->whenElapsed) / timer->repeatInterval);
        auto delta = count * timer->repeatInterval;
        auto nextElapsed = timer->whenElapsed + delta;
        SetHandlerLocked(timer->name, timer->id, timer->type, timer->when + delta, nextElapsed, timer->windowLength,
            MaxTriggerTime(nowElapsed, nextElapsed, timer->repeatInterval), timer->repeatInterval, timer->callback,
            timer->wantAgent, timer->flags, timer->autoRestore, timer->uid, timer->pid, timer->bundleName);
    } else {
        TimerProxy::GetInstance().RemoveUidTimerMap(timer);
        TimerProxy::GetInstance().RemovePidTimerMap(timer);
    }
}

inline bool TimerManager::CheckNeedRecoverOnReboot(std::string bundleName, int type, bool autoRestore)
{
    return ((std::find(NEED_RECOVER_ON_REBOOT.begin(), NEED_RECOVER_ON_REBOOT.end(), bundleName) !=
        NEED_RECOVER_ON_REBOOT.end() && (type == RTC || type == RTC_WAKEUP)) || autoRestore);
}

#ifdef POWER_MANAGER_ENABLE
// needs to acquire the lock `mutex_` before calling this method
void TimerManager::HandleRunningLock(const std::shared_ptr<Batch> &firstWakeup)
{
    auto currentTime = duration_cast<nanoseconds>(GetBootTimeNs().time_since_epoch()).count();
    auto nextTimerOffset =
        duration_cast<nanoseconds>(firstWakeup->GetStart().time_since_epoch()).count() - currentTime;
    auto lockOffset = currentTime - lockExpiredTime_;
    if (nextTimerOffset > 0 && nextTimerOffset <= USE_LOCK_TIME_IN_NANO &&
        ((lockOffset < 0 && std::abs(lockOffset) <= nextTimerOffset) || lockOffset >= 0)) {
        auto firstAlarm = firstWakeup->Get(0);
        if (firstAlarm == nullptr) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "first alarm is null");
            return;
        }
        auto holdLockTime = nextTimerOffset + ONE_HUNDRED_MILLI;
        TIME_HILOGI(TIME_MODULE_SERVICE, "runningLock time:%{public}" PRIu64 ", timerId:%{public}"
                    PRIu64", uid:%{public}d  bundleName=%{public}s", static_cast<uint64_t>(holdLockTime),
                    firstAlarm->id, firstAlarm->uid, firstAlarm->bundleName.c_str());
        lockExpiredTime_ = currentTime + holdLockTime;
        AddRunningLock(holdLockTime);
    }
}

void TimerManager::AddRunningLockRetry(long long holdLockTime)
{
    auto retryRegister = [this, holdLockTime]() {
        for (int i = 0; i < POWER_RETRY_TIMES; i++) {
            usleep(POWER_RETRY_INTERVAL);
            runningLock_->Lock(static_cast<int32_t>(holdLockTime / NANO_TO_MILLI));
            if (runningLock_->IsUsed()) {
                return;
            }
        }
    };
    std::thread thread(retryRegister);
    thread.detach();
}

void TimerManager::AddRunningLock(long long holdLockTime)
{
    if (runningLock_ == nullptr) {
        std::lock_guard<std::mutex> lock(runningLockMutex_);
        if (runningLock_ == nullptr) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "runningLock is nullptr, create runningLock");
            runningLock_ = PowerMgr::PowerMgrClient::GetInstance().CreateRunningLock("timeServiceRunningLock",
                PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
        }
    }
    if (runningLock_ != nullptr) {
        runningLock_->Lock(static_cast<int32_t>(holdLockTime / NANO_TO_MILLI));
        if (!runningLock_->IsUsed()) {
            AddRunningLockRetry(holdLockTime);
        }
    }
}
#endif
} // MiscServices
} // OHOS