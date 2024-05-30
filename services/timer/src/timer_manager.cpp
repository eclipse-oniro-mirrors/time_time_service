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
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#ifdef DEVICE_STANDBY_ENABLE
#include "allow_type.h"
#include "standby_service_client.h"
#endif
#include "ipc_skeleton.h"
#include "time_file_utils.h"
#include "time_permission.h"
#include "timer_proxy.h"
#include "time_sysevent.h"
#include "timer_database.h"
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
static const std::vector<std::string> ALL_DATA = { "timerId", "type", "flag", "windowLength", "interval", \
                                                   "uid", "bundleName", "wantAgent", "state", "triggerTime" };

#ifdef POWER_MANAGER_ENABLE
constexpr int64_t USE_LOCK_ONE_SEC_IN_NANO = 1 * NANO_TO_SECOND;
constexpr int64_t USE_LOCK_TIME_IN_NANO = 2 * NANO_TO_SECOND;
constexpr int32_t USE_LOCK_DELAY_TIME_IN_MICRO = 10000;
constexpr int32_t MAX_RETRY_LOCK_TIMES = 3;
constexpr int32_t NANO_TO_MILLI = 1000000;
constexpr int64_t ONE_HUNDRED_MILLI = 100000000; // 100ms
#endif

#ifdef DEVICE_STANDBY_ENABLE
const int REASON_NATIVE_API = 0;
const int REASON_APP_API = 1;
#endif
}

extern bool AddBatchLocked(std::vector<std::shared_ptr<Batch>> &list, const std::shared_ptr<Batch> &batch);
extern steady_clock::time_point MaxTriggerTime(steady_clock::time_point now,
                                               steady_clock::time_point triggerAtTime,
                                               milliseconds interval);

std::shared_ptr<TimerManager> TimerManager::Create()
{
    auto impl = TimerHandler::Create();
    if (impl == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Create Timer handle failed.");
        return nullptr;
    }
    return std::shared_ptr<TimerManager>(new TimerManager(impl));
}

TimerManager::TimerManager(std::shared_ptr<TimerHandler> impl)
    : random_ {static_cast<uint64_t>(time(nullptr))},
      runFlag_ {true},
      handler_ {std::move(impl)},
      lastTimeChangeClockTime_ {system_clock::time_point::min()},
      lastTimeChangeRealtime_ {steady_clock::time_point::min()}
{
    alarmThread_.reset(new std::thread(&TimerManager::TimerLooper, this));
}

OHOS::NativeRdb::ValuesBucket GetInsertValues(uint64_t &timerId, TimerPara &paras,
                                              int uid, std::string bundleName,
                                              std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent)
{
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("timerId", timerId);
    insertValues.PutInt("type", paras.timerType);
    insertValues.PutInt("flag", paras.flag);
    insertValues.PutLong("windowLength", paras.windowLength);
    insertValues.PutLong("interval", paras.interval);
    insertValues.PutInt("uid", uid);
    insertValues.PutString("bundleName", bundleName);
    insertValues.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues.PutInt("state", 0);
    insertValues.PutLong("triggerTime", 0);
    return insertValues;
}

int32_t TimerManager::CreateTimer(TimerPara &paras,
                                  std::function<void (const uint64_t)> callback,
                                  std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                                  int uid,
                                  int pid,
                                  uint64_t &timerId,
                                  DatabaseType type)
{
    while (timerId == 0) {
        timerId = random_();
    }
    TIME_HILOGI(TIME_MODULE_SERVICE,
                "Create timer: %{public}d windowLength:%{public}" PRId64 "interval:%{public}" PRId64 "flag:%{public}d"
                "uid:%{public}d pid:%{public}d timerId:%{public}" PRId64 "", paras.timerType, paras.windowLength,
                paras.interval, paras.flag, IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid(), timerId);
    std::string bundleName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    if (bundleName.empty()) {
        bundleName = TimeFileUtils::GetNameByPid(IPCSkeleton::GetCallingPid());
    }
    auto timerInfo = std::make_shared<TimerEntry>(TimerEntry {
        timerId,
        paras.timerType,
        static_cast<uint64_t>(paras.windowLength),
        paras.interval,
        paras.flag,
        std::move(callback),
        wantAgent,
        uid,
        pid,
        bundleName
    });
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    timerEntryMap_.insert(std::make_pair(timerId, timerInfo));

    if (type == NOT_STORE) {
        return E_TIME_OK;
    } else if (bundleName == NEED_RECOVER_ON_REBOOT) {
        OHOS::NativeRdb::ValuesBucket insertValues = GetInsertValues(timerId, paras, uid, bundleName, wantAgent);
        TimeDatabase::GetInstance().Insert(std::string(HOLD_ON_REBOOT), insertValues);
    } else {
        OHOS::NativeRdb::ValuesBucket insertValues = GetInsertValues(timerId, paras, uid, bundleName, wantAgent);
        TimeDatabase::GetInstance().Insert(std::string(DROP_ON_REBOOT), insertValues);
    }
    return E_TIME_OK;
}

void TimerManager::ReCreateTimer(uint64_t timerId, std::shared_ptr<TimerEntry> timerInfo)
{
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    timerEntryMap_.insert(std::make_pair(timerId, timerInfo));
}

int32_t TimerManager::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    auto it = timerEntryMap_.find(timerId);
    if (it == timerEntryMap_.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer id not found: %{public}" PRId64 "", timerId);
        return E_TIME_NOT_FOUND;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE,
        "Start timer: %{public}" PRIu64 " TriggerTime: %{public}s uid:%{public}d pid:%{public}d",
        timerId, std::to_string(triggerTime).c_str(), IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    auto timerInfo = it->second;
    if (TimerProxy::GetInstance().IsUidProxy(timerInfo->uid)) {
        TIME_HILOGI(TIME_MODULE_SERVICE,
            "Do not start timer, timer already proxy, id=%{public}" PRIu64 ", uid = %{public}d",
            timerInfo->id, timerInfo->uid);
        return E_TIME_DEAL_FAILED;
    } else if (TimerProxy::GetInstance().IsPidProxy(timerInfo->pid)) {
        TIME_HILOGI(TIME_MODULE_SERVICE,
            "Do not start timer, timer already proxy, id=%{public}" PRIu64 ", pid = %{public}d",
            timerInfo->id, timerInfo->pid);
        return E_TIME_DEAL_FAILED;
    }
    SetHandler(timerInfo->id,
               timerInfo->type,
               triggerTime,
               timerInfo->windowLength,
               timerInfo->interval,
               timerInfo->flag,
               timerInfo->callback,
               timerInfo->wantAgent,
               timerInfo->uid,
               timerInfo->pid,
               timerInfo->bundleName);
    if (timerInfo->bundleName == NEED_RECOVER_ON_REBOOT) {
        OHOS::NativeRdb::ValuesBucket values;
        values.PutInt("state", 1);
        values.PutLong("triggerTime", static_cast<int64_t>(triggerTime));
        OHOS::NativeRdb::RdbPredicates rdbPredicates(HOLD_ON_REBOOT);
        rdbPredicates.EqualTo("state", 0)->And()->EqualTo("timerId", static_cast<int64_t>(timerId));
        TimeDatabase::GetInstance().Update(values, rdbPredicates);
    } else {
        OHOS::NativeRdb::ValuesBucket values;
        values.PutInt("state", 1);
        values.PutLong("triggerTime", static_cast<int64_t>(triggerTime));
        OHOS::NativeRdb::RdbPredicates rdbPredicates(DROP_ON_REBOOT);
        rdbPredicates.EqualTo("state", 0)->And()->EqualTo("timerId", static_cast<int64_t>(timerId));
        TimeDatabase::GetInstance().Update(values, rdbPredicates);
    }
    return E_TIME_OK;
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
    TIME_HILOGI(TIME_MODULE_SERVICE, "id: %{public}" PRId64 ", needDestroy: %{public}d",
        timerNumber, needDestroy);
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    auto it = timerEntryMap_.find(timerNumber);
    if (it == timerEntryMap_.end()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "timer not exist");
        return E_TIME_DEAL_FAILED;
    }
    RemoveHandler(timerNumber);
    if (it->second) {
        int32_t uid = it->second->uid;
        int32_t pid = it->second->pid;
        TimerProxy::GetInstance().RemoveProxy(timerNumber, uid);
        TimerProxy::GetInstance().RemovePidProxy(timerNumber, pid);
        TimerProxy::GetInstance().EraseTimerFromProxyUidMap(timerNumber, uid);
        TimerProxy::GetInstance().EraseTimerFromProxyPidMap(timerNumber, pid);
    }
    std::string bundleName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    if (bundleName == NEED_RECOVER_ON_REBOOT) {
        OHOS::NativeRdb::ValuesBucket values;
        values.PutInt("state", 0);
        OHOS::NativeRdb::RdbPredicates rdbPredicates(HOLD_ON_REBOOT);
        rdbPredicates.EqualTo("state", 1)
            ->And()
            ->EqualTo("timerId", static_cast<int64_t>(timerNumber));
        TimeDatabase::GetInstance().Update(values, rdbPredicates);
        if (needDestroy) {
            timerEntryMap_.erase(it);
            OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(HOLD_ON_REBOOT);
            rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(timerNumber));
            TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
        }
    } else {
        OHOS::NativeRdb::ValuesBucket values;
        values.PutInt("state", 0);
        OHOS::NativeRdb::RdbPredicates rdbPredicates(DROP_ON_REBOOT);
        rdbPredicates.EqualTo("state", 1)
            ->And()
            ->EqualTo("timerId", static_cast<int64_t>(timerNumber));
        TimeDatabase::GetInstance().Update(values, rdbPredicates);
        if (needDestroy) {
            timerEntryMap_.erase(it);
            OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(DROP_ON_REBOOT);
            rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(timerNumber));
            TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
        }
    }
    return E_TIME_OK;
}

void TimerManager::SetHandler(uint64_t id,
                              int type,
                              uint64_t triggerAtTime,
                              uint64_t windowLength,
                              uint64_t interval,
                              int flag,
                              std::function<void (const uint64_t)> callback,
                              std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                              int uid,
                              int pid,
                              const std::string &bundleName)
{
    auto windowLengthDuration = milliseconds(windowLength);
    if (windowLengthDuration > INTERVAL_HALF_DAY) {
        windowLengthDuration = INTERVAL_HOUR;
    }
    auto minInterval = MIN_INTERVAL_ONE_SECONDS;
    auto intervalDuration = milliseconds(interval);
    if (intervalDuration > milliseconds::zero() && intervalDuration < minInterval) {
        intervalDuration = minInterval;
    } else if (intervalDuration > MAX_INTERVAL) {
        intervalDuration = MAX_INTERVAL;
    }

    auto nowElapsed = GetBootTimeNs();
    auto nominalTrigger = ConvertToElapsed(milliseconds(triggerAtTime), type);
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
    TIME_HILOGD(TIME_MODULE_SERVICE, "Try get lock");
    std::lock_guard<std::mutex> lockGuard(mutex_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "Lock guard");
    SetHandlerLocked(id,
                     type,
                     milliseconds(triggerAtTime),
                     triggerElapsed,
                     windowLengthDuration,
                     maxElapsed,
                     intervalDuration,
                     std::move(callback),
                     wantAgent,
                     static_cast<uint32_t>(flag),
                     uid,
                     pid,
                     bundleName);
}

void TimerManager::SetHandlerLocked(uint64_t id, int type,
                                    std::chrono::milliseconds when,
                                    std::chrono::steady_clock::time_point whenElapsed,
                                    std::chrono::milliseconds windowLength,
                                    std::chrono::steady_clock::time_point maxWhen,
                                    std::chrono::milliseconds interval,
                                    std::function<void (const uint64_t)> callback,
                                    const std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> &wantAgent,
                                    uint32_t flags,
                                    uint64_t callingUid,
                                    uint64_t callingPid,
                                    const std::string &bundleName)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start id: %{public}" PRId64 "", id);
    auto alarm = std::make_shared<TimerInfo>(id, type, when, whenElapsed, windowLength, maxWhen,
                                             interval, std::move(callback), wantAgent, flags, callingUid,
                                             callingPid, bundleName);
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
    TIME_HILOGI(TIME_MODULE_SERVICE, "start id: %{public}" PRIu64 "", id);
    auto whichAlarms = [id](const TimerInfo &timer) {
        return timer.id == id;
    };

    bool didRemove = false;
    for (auto it = alarmBatches_.begin(); it != alarmBatches_.end();) {
        auto batch = *it;
        didRemove = batch->Remove(whichAlarms);
        if (batch->Size() == 0) {
            TIME_HILOGD(TIME_MODULE_SERVICE, "erase");
            it = alarmBatches_.erase(it);
        } else {
            ++it;
        }
        if (didRemove) {
            break;
        }
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
        TIME_HILOGI(TIME_MODULE_SERVICE, "result: %{public}u", result);
        auto nowRtc = std::chrono::system_clock::now();
        auto nowElapsed = GetBootTimeNs();
        triggerList.clear();

        if ((result & TIME_CHANGED_MASK) != 0) {
            system_clock::time_point lastTimeChangeClockTime;
            system_clock::time_point expectedClockTime;
            std::lock_guard<std::mutex> lock(mutex_);
            lastTimeChangeClockTime = lastTimeChangeClockTime_;
            expectedClockTime = lastTimeChangeClockTime +
                (duration_cast<milliseconds>(nowElapsed.time_since_epoch()) -
                duration_cast<milliseconds>(lastTimeChangeRealtime_.time_since_epoch()));
            if (lastTimeChangeClockTime == system_clock::time_point::min()
                || nowRtc < (expectedClockTime - milliseconds(ONE_THOUSAND))
                || nowRtc > (expectedClockTime + milliseconds(ONE_THOUSAND))) {
                ReBatchAllTimers();
                lastTimeChangeClockTime_ = nowRtc;
                lastTimeChangeRealtime_ = nowElapsed;
            }
        }

        if (result != TIME_CHANGED_MASK) {
            std::lock_guard<std::mutex> lock(mutex_);
            TriggerTimersLocked(triggerList, nowElapsed);
            DeliverTimersLocked(triggerList);
            RescheduleKernelTimerLocked();
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            RescheduleKernelTimerLocked();
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
void TimerManager::ProcTriggerTimer(std::shared_ptr<TimerInfo> &alarm,
    std::vector<std::shared_ptr<TimerInfo>> &triggerList, const std::chrono::steady_clock::time_point &nowElapsed)
{
    alarm->count = 1;
    if (mPendingIdleUntil_ != nullptr && mPendingIdleUntil_->id == alarm->id) {
        TriggerIdleTimer();
    }
    if (TimerProxy::GetInstance().IsUidProxy(alarm->uid)) {
        alarm->UpdateWhenElapsedFromNow(nowElapsed, milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
        TIME_HILOGD(TIME_MODULE_SERVICE, "UpdateWhenElapsed for proxy timer trigger. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            alarm->uid, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
            nowElapsed.time_since_epoch().count());
        SetHandlerLocked(alarm->id, alarm->type, alarm->when, alarm->whenElapsed, alarm->windowLength,
            alarm->maxWhenElapsed, alarm->repeatInterval, alarm->callback,
            alarm->wantAgent, alarm->flags, alarm->uid, alarm->pid, alarm->bundleName);
    } else if (TimerProxy::GetInstance().IsPidProxy(alarm->pid)) {
        alarm->UpdateWhenElapsedFromNow(nowElapsed, milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
        TIME_HILOGD(TIME_MODULE_SERVICE, "UpdateWhenElapsed for proxy timer trigger. "
            "pid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            alarm->pid, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
            nowElapsed.time_since_epoch().count());
        SetHandlerLocked(alarm->id, alarm->type, alarm->when, alarm->whenElapsed, alarm->windowLength,
            alarm->maxWhenElapsed, alarm->repeatInterval, alarm->callback,
            alarm->wantAgent, alarm->flags, alarm->uid, alarm->pid, alarm->bundleName);
    } else {
        triggerList.push_back(alarm);
        HandleRepeatTimer(alarm, nowElapsed);
    }
}

// needs to acquire the lock `mutex_` before calling this method
bool TimerManager::TriggerTimersLocked(std::vector<std::shared_ptr<TimerInfo>> &triggerList,
                                       std::chrono::steady_clock::time_point nowElapsed)
{
    bool hasWakeup = false;
    TIME_HILOGD(TIME_MODULE_SERVICE, "current time %{public}lld", GetBootTimeNs().time_since_epoch().count());

    for (auto iter = alarmBatches_.begin(); iter != alarmBatches_.end();) {
        if ((*iter)->GetStart() > nowElapsed) {
            ++iter;
            continue;
        }
        auto batch = *iter;
        iter = alarmBatches_.erase(iter);
        TIME_HILOGI(
            TIME_MODULE_SERVICE, "after erase alarmBatches_.size= %{public}d", static_cast<int>(alarmBatches_.size()));
        const auto n = batch->Size();
        for (unsigned int i = 0; i < n; ++i) {
            auto alarm = batch->Get(i);
            ProcTriggerTimer(alarm, triggerList, nowElapsed);
            TIME_HILOGI(TIME_MODULE_SERVICE, "alarm uid= %{public}d, id=%{public}" PRId64 " bundleName=%{public}s",
                alarm->uid, alarm->id, alarm->bundleName.c_str());

            if (alarm->wakeup) {
                hasWakeup = true;
            }
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
    auto nextNonWakeup = std::chrono::steady_clock::time_point::min();
    if (!alarmBatches_.empty()) {
        auto firstWakeup = FindFirstWakeupBatchLocked();
        auto firstBatch = alarmBatches_.front();
        if (firstWakeup != nullptr) {
            #ifdef POWER_MANAGER_ENABLE
            HandleRunningLock(firstWakeup);
            #endif
            auto alarmPtr = firstWakeup->Get(0);
            TIME_HILOGI(TIME_MODULE_SERVICE, "wakeup: next trigger timer id: %{public}" PRIu64 ""
                        "uid: %{public}d, trigger time  %{public}lld", alarmPtr->id,
                        alarmPtr->uid, alarmPtr->whenElapsed.time_since_epoch().count());
            SetLocked(ELAPSED_REALTIME_WAKEUP, firstWakeup->GetStart().time_since_epoch());
        }
        if (firstBatch != firstWakeup) {
            auto alarmPtr = firstBatch->Get(0);
            nextNonWakeup = firstBatch->GetStart();
            TIME_HILOGI(TIME_MODULE_SERVICE, "nonwakeup: next trigger timer id: %{public}" PRIu64 ""
                        "uid: %{public}d, trigger time  %{public}lld", alarmPtr->id,
                        alarmPtr->uid, alarmPtr->whenElapsed.time_since_epoch().count());
        }
    }

    if (nextNonWakeup != std::chrono::steady_clock::time_point::min()) {
        SetLocked(ELAPSED_REALTIME, nextNonWakeup.time_since_epoch());
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

void TimerManager::SetLocked(int type, std::chrono::nanoseconds when)
{
    handler_->Set(static_cast<uint32_t>(type), when, GetBootTimeNs());
}

// needs to acquire the lock `mutex_` before calling this method
void TimerManager::InsertAndBatchTimerLocked(std::shared_ptr<TimerInfo> alarm)
{
    int64_t whichBatch = (alarm->flags & static_cast<uint32_t>(STANDALONE)) ?
                         -1 :
                         AttemptCoalesceLocked(alarm->whenElapsed, alarm->maxWhenElapsed);
    TIME_HILOGI(TIME_MODULE_SERVICE, "whichBatch= %{public}" PRId64 ", id=%{public}" PRIu64 ","
                "whenElapsed=%{public}lld , maxWhenElapsed=%{public}lld",
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

void TimerManager::DeliverTimersLocked(const std::vector<std::shared_ptr<TimerInfo>> &triggerList)
{
    auto wakeupNums = std::count_if(triggerList.begin(), triggerList.end(), [](auto timer) {return timer->wakeup;});
    for (const auto &timer : triggerList) {
        if (timer->wakeup) {
            #ifdef POWER_MANAGER_ENABLE
            TIME_HILOGI(TIME_MODULE_SERVICE, "id: %{public}" PRId64 ", uid: %{public}d bundleName: %{public}s",
                        timer->id, timer->uid, timer->bundleName.c_str());
            AddRunningLock(USE_LOCK_ONE_SEC_IN_NANO);
            #endif
            StatisticReporter(IPCSkeleton::GetCallingPid(), wakeupNums, timer);
        }
        if (timer->callback) {
            TimerProxy::GetInstance().CallbackAlarmIfNeed(timer);
        }
        if (timer->wantAgent) {
            NotifyWantAgent(timer);
            if (timer->bundleName == NEED_RECOVER_ON_REBOOT) {
                OHOS::NativeRdb::ValuesBucket values;
                values.PutInt("state", 0);
                OHOS::NativeRdb::RdbPredicates rdbPredicates(HOLD_ON_REBOOT);
                rdbPredicates.EqualTo("state", 1)
                    ->And()
                    ->EqualTo("timerId", static_cast<int64_t>(timer->id));
                TimeDatabase::GetInstance().Update(values, rdbPredicates);
            } else {
                OHOS::NativeRdb::ValuesBucket values;
                values.PutInt("state", 0);
                OHOS::NativeRdb::RdbPredicates rdbPredicates(DROP_ON_REBOOT);
                rdbPredicates.EqualTo("state", 1)
                    ->And()
                    ->EqualTo("timerId", static_cast<int64_t>(timer->id));
                TimeDatabase::GetInstance().Update(values, rdbPredicates);
            }
        }
    }
}

bool TimerManager::NotifyWantAgent(const std::shared_ptr<TimerInfo> &timer)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "trigger wantAgent.");
    auto wantAgent = timer->wantAgent;
    std::shared_ptr<AAFwk::Want> want = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
    if (want == nullptr) {
        auto database = TimeDatabase::GetInstance();
        OHOS::NativeRdb::RdbPredicates holdRdbPredicates(HOLD_ON_REBOOT);
        holdRdbPredicates.EqualTo("timerId", static_cast<int64_t>(timer->id));
        auto holdResultSet = database.Query(holdRdbPredicates, ALL_DATA);
        if (holdResultSet == nullptr || holdResultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "want is nullptr");
            return false;
        }
        // Line 7 is 'wantAgent'
        wantAgent = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::FromString(GetString(holdResultSet, 7));
        want = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
    }
    OHOS::AbilityRuntime::WantAgent::TriggerInfo paramsInfo("", nullptr, want, WANTAGENT_CODE_ELEVEN);
    auto code = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(wantAgent, nullptr, paramsInfo);
    TIME_HILOGI(TIME_MODULE_SERVICE, "trigger wantAgent result: %{public}d", code);
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

bool TimerManager::ProxyTimer(std::set<int> pidList, bool isProxy, bool needRetrigger)
{
    std::set<int> failurePid;
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::set<int>::iterator pid = pidList.begin(); pid != pidList.end(); ++pid) {
        if (!TimerProxy::GetInstance().PidProxyTimer(*pid, isProxy, needRetrigger, GetBootTimeNs(),
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
    TIME_HILOGI(TIME_MODULE_SERVICE, "start adjust timer, uid=%{public}d, id=%{public}" PRId64 "",
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
        TIME_HILOGI(TIME_MODULE_SERVICE, "Timer unrestricted, not adjust. id=%{public}" PRId64 "", alarm->id);
        return false;
    } else if (alarm->whenElapsed > mPendingIdleUntil_->whenElapsed) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Timer not allowed, not adjust. id=%{public}" PRId64 "", alarm->id);
        return false;
    } else {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Timer not allowed, id=%{public}" PRId64 "", alarm->id);
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
        dprintf(fd, " * timer id            = %lu\n", iter->second->id);
        dprintf(fd, " * timer type          = %d\n", iter->second->type);
        dprintf(fd, " * timer flag          = %lu\n", iter->second->flag);
        dprintf(fd, " * timer window Length = %lu\n", iter->second->windowLength);
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
        dprintf(fd, " * timer window Length = %lu\n", iter->second->windowLength);
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
        timer->count += static_cast<uint64_t>(
            duration_cast<milliseconds>(nowElapsed - timer->expectedWhenElapsed) / timer->repeatInterval);
        auto delta = timer->count * timer->repeatInterval;
        auto nextElapsed = timer->whenElapsed + delta;
        SetHandlerLocked(timer->id, timer->type, timer->when + delta, nextElapsed, timer->windowLength,
            MaxTriggerTime(nowElapsed, nextElapsed, timer->repeatInterval), timer->repeatInterval, timer->callback,
            timer->wantAgent, timer->flags, timer->uid, timer->pid, timer->bundleName);
    } else {
        TimerProxy::GetInstance().RemoveUidTimerMap(timer);
        TimerProxy::GetInstance().RemovePidTimerMap(timer);
    }
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
        std::thread lockingThread([this, holdLockTime] {
            TIME_HILOGI(TIME_MODULE_SERVICE, "start add runningLock thread");
            int32_t retryCount = 0;
            while (retryCount < MAX_RETRY_LOCK_TIMES) {
                AddRunningLock(holdLockTime);
                usleep(USE_LOCK_DELAY_TIME_IN_MICRO);
                ++retryCount;
            }
        });
        lockingThread.detach();
    }
}

void TimerManager::AddRunningLock(long long holdLockTime)
{
    if (runningLock_ == nullptr) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "runningLock is nullptr, create runningLock");
        runningLock_ = PowerMgr::PowerMgrClient::GetInstance().CreateRunningLock("timeServiceRunningLock",
            PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND_NOTIFICATION);
    }
    if (runningLock_ != nullptr) {
        runningLock_->UnLock();
        runningLock_->Lock(static_cast<int32_t>(holdLockTime / NANO_TO_MILLI));
    }
}
#endif
} // MiscServices
} // OHOS