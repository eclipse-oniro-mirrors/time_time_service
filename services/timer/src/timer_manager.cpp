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

#ifdef POWER_MANAGER_ENABLE
constexpr int64_t USE_LOCK_TIME_IN_NANO = NANO_TO_SECOND;
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

int32_t TimerManager::CreateTimer(TimerPara &paras,
                                  std::function<void (const uint64_t)> callback,
                                  std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                                  int uid,
                                  uint64_t &timerId)
{
    while (timerId == 0) {
        timerId = random_();
    }
    TIME_HILOGI(TIME_MODULE_SERVICE,
                "Create timer: %{public}d windowLength:%{public}" PRId64 "interval:%{public}" PRId64 "flag:%{public}d"
                "uid:%{public}d pid:%{public}d", paras.timerType, paras.windowLength, paras.interval, paras.flag,
                IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    std::string bundleName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    auto timerInfo = std::make_shared<TimerEntry>(TimerEntry {
        timerId,
        paras.timerType,
        static_cast<uint64_t>(paras.windowLength),
        paras.interval,
        paras.flag,
        std::move(callback),
        wantAgent,
        uid,
        bundleName
    });
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    timerEntryMap_.insert(std::make_pair(timerId, timerInfo));
    return E_TIME_OK;
}

int32_t TimerManager::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    std::lock_guard<std::mutex> lock(entryMapMutex_);
    auto it = timerEntryMap_.find(timerId);
    if (it == timerEntryMap_.end()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer id not found: %{public}" PRId64 "", timerId);
        return E_TIME_NOT_FOUND;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Start timer: %{public}" PRIu64 " TriggerTime: %{public}" PRIu64""
                "uid:%{public}d pid:%{public}d", timerId, triggerTime, IPCSkeleton::GetCallingUid(),
                IPCSkeleton::GetCallingPid());
    auto timerInfo = it->second;
    if (TimerProxy::GetInstance().IsUidProxy(timerInfo->uid)) {
        TIME_HILOGI(TIME_MODULE_SERVICE,
            "Do not start timer, timer already proxy, id=%{public}" PRId64 ", uid = %{public}d",
            timerInfo->id, timerInfo->uid);
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
               timerInfo->bundleName);
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
    TIME_HILOGI(TIME_MODULE_SERVICE, "start id: %{public}" PRId64 ", needDestroy: %{public}d",
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
        TimerProxy::GetInstance().RemoveProxy(timerNumber, uid);
        TimerProxy::GetInstance().EraseTimerFromProxyUidMap(timerNumber, uid);
    }
    if (needDestroy) {
        timerEntryMap_.erase(it);
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
                              const std::string &bundleName)
{
    TIME_HILOGI(TIME_MODULE_SERVICE,
                "start type:%{public}d windowLength:%{public}" PRIu64"interval:%{public}" PRIu64"flag:%{public}d",
        type, windowLength, interval, flag);
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
    if (nominalTrigger < nowElapsed) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "invalid trigger time.");
        return;
    }
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
                     true,
                     uid,
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
                                    bool doValidate,
                                    uint64_t callingUid,
                                    const std::string &bundleName)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start id: %{public}" PRId64 "", id);
    auto alarm = std::make_shared<TimerInfo>(id, type, when, whenElapsed, windowLength, maxWhen,
                                             interval, std::move(callback), wantAgent, flags, callingUid, bundleName);
    SetHandlerLocked(alarm, false, doValidate, false);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
}

void TimerManager::RemoveHandler(uint64_t id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RemoveLocked(id);
    TimerProxy::GetInstance().RemoveUidTimerMap(id);
}

void TimerManager::RemoveLocked(uint64_t id)
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
    }
    pendingDelayTimers_.erase(remove_if(pendingDelayTimers_.begin(), pendingDelayTimers_.end(),
        [id](const std::shared_ptr<TimerInfo> &timer) {
            return timer->id == id;
        }), pendingDelayTimers_.end());
    delayedTimers_.erase(id);
    bool isAdjust = false;
    if (mPendingIdleUntil_ != nullptr && id == mPendingIdleUntil_->id) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Idle alarm removed.");
        mPendingIdleUntil_ = nullptr;
        isAdjust = AdjustTimersBasedOnDeviceIdle();
        delayedTimers_.clear();
        for (const auto &pendingTimer : pendingDelayTimers_) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Set timer from delay list, id=%{public}" PRId64 "", pendingTimer->id);
            if (pendingTimer->whenElapsed <= GetBootTimeNs()) {
                // 2 means the time of performing task.
                pendingTimer->UpdateWhenElapsed(GetBootTimeNs(), milliseconds(2));
            } else {
                pendingTimer->UpdateWhenElapsed(GetBootTimeNs(), pendingTimer->offset);
            }
            SetHandlerLocked(pendingTimer, false, true, false);
        }
        pendingDelayTimers_.clear();
    }

    if (didRemove || isAdjust) {
        ReBatchAllTimersLocked(true);
    }
}

void TimerManager::SetHandlerLocked(std::shared_ptr<TimerInfo> alarm, bool rebatching, bool doValidate,
                                    bool isRebatched)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start rebatching= %{public}d, doValidate= %{public}d", rebatching, doValidate);
    TimerProxy::GetInstance().RecordUidTimerMap(alarm, isRebatched);

    if (!isRebatched && mPendingIdleUntil_ != nullptr && !CheckAllowWhileIdle(alarm)) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Pending not-allowed alarm in idle state, id=%{public}" PRId64 "",
            alarm->id);
        alarm->offset = duration_cast<milliseconds>(alarm->whenElapsed - GetBootTimeNs());
        pendingDelayTimers_.push_back(alarm);
        return;
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

void TimerManager::ReBatchAllTimers()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    ReBatchAllTimersLocked(true);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
}

void TimerManager::ReBatchAllTimersLocked(bool doValidate)
{
    auto oldSet = alarmBatches_;
    alarmBatches_.clear();
    auto nowElapsed = GetBootTimeNs();
    for (const auto &batch : oldSet) {
        auto n = batch->Size();
        for (unsigned int i = 0; i < n; i++) {
            ReAddTimerLocked(batch->Get(i), nowElapsed, doValidate);
        }
    }
    RescheduleKernelTimerLocked();
}

void TimerManager::ReAddTimerLocked(std::shared_ptr<TimerInfo> timer,
                                    std::chrono::steady_clock::time_point nowElapsed,
                                    bool doValidate)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "ReAddTimerLocked start. uid= %{public}d, id=%{public}" PRId64 ""
        ", timer whenElapsed=%{public}lld, now=%{public}lld",
        timer->uid, timer->id, timer->whenElapsed.time_since_epoch().count(),
        GetBootTimeNs().time_since_epoch().count());
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
    SetHandlerLocked(timer, true, doValidate, true);
}

std::chrono::steady_clock::time_point TimerManager::ConvertToElapsed(std::chrono::milliseconds when, int type)
{
    auto bootTimePoint = GetBootTimeNs();
    if (type == RTC || type == RTC_WAKEUP) {
        auto systemTimeNow = system_clock::now().time_since_epoch();
        auto offset = when - systemTimeNow;
        TIME_HILOGD(TIME_MODULE_SERVICE, "systemTimeNow : %{public}lld offset : %{public}lld",
                    systemTimeNow.count(), offset.count());
        return bootTimePoint + offset;
    }
    auto bootTimeNow = bootTimePoint.time_since_epoch();
    auto offset = when - bootTimeNow;
    TIME_HILOGD(TIME_MODULE_SERVICE, "bootTimeNow : %{public}lld offset : %{public}lld",
                bootTimeNow.count(), offset.count());
    return bootTimePoint + offset;
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

void TimerManager::TriggerIdleTimer()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Idle alarm triggers.");
    std::lock_guard<std::mutex> lock(idleTimerMutex_);
    mPendingIdleUntil_ = nullptr;
    delayedTimers_.clear();
    std::for_each(pendingDelayTimers_.begin(), pendingDelayTimers_.end(),
        [this](const std::shared_ptr<TimerInfo> &pendingTimer) {
            TIME_HILOGI(TIME_MODULE_SERVICE, "Set timer from delay list, id=%{public}" PRId64 "", pendingTimer->id);
            if (pendingTimer->whenElapsed > GetBootTimeNs()) {
                pendingTimer->UpdateWhenElapsed(GetBootTimeNs(), pendingTimer->offset);
            } else {
                // 2 means the time of performing task.
                pendingTimer->UpdateWhenElapsed(GetBootTimeNs(), milliseconds(2));
            }
            SetHandlerLocked(pendingTimer, false, true, false);
        });
    pendingDelayTimers_.clear();
    ReBatchAllTimers();
}

void TimerManager::ProcTriggerTimer(std::shared_ptr<TimerInfo> &alarm,
    std::vector<std::shared_ptr<TimerInfo>> &triggerList, const std::chrono::steady_clock::time_point &nowElapsed)
{
    alarm->count = 1;
    if (mPendingIdleUntil_ != nullptr && mPendingIdleUntil_->id == alarm->id) {
        TriggerIdleTimer();
    }
    if (TimerProxy::GetInstance().IsUidProxy(alarm->uid)) {
        alarm->UpdateWhenElapsed(nowElapsed, milliseconds(TimerProxy::GetInstance().GetProxyDelayTime()));
        TIME_HILOGD(TIME_MODULE_SERVICE, "UpdateWhenElapsed for proxy timer trigger. "
            "uid= %{public}d, id=%{public}" PRId64 ", timer whenElapsed=%{public}lld, now=%{public}lld",
            alarm->uid, alarm->id, alarm->whenElapsed.time_since_epoch().count(),
            nowElapsed.time_since_epoch().count());
        SetHandlerLocked(alarm->id, alarm->type, alarm->when, alarm->whenElapsed, alarm->windowLength,
            alarm->maxWhenElapsed, alarm->repeatInterval, alarm->callback,
            alarm->wantAgent, alarm->flags, true, alarm->uid, alarm->bundleName);
    } else {
        triggerList.push_back(alarm);
        HandleRepeatTimer(alarm, nowElapsed);
    }
}

bool TimerManager::TriggerTimersLocked(std::vector<std::shared_ptr<TimerInfo>> &triggerList,
                                       std::chrono::steady_clock::time_point nowElapsed)
{
    bool hasWakeup = false;
    TIME_HILOGD(TIME_MODULE_SERVICE, "current time %{public}lld", GetBootTimeNs().time_since_epoch().count());
    while (!alarmBatches_.empty()) {
        auto batch = alarmBatches_.at(0);
        TIME_HILOGD(TIME_MODULE_SERVICE, "first batch trigger time %{public}lld",
            batch->GetStart().time_since_epoch().count());
        if (batch->GetStart() > nowElapsed) {
            break;
        }
        alarmBatches_.erase(alarmBatches_.begin());
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
            SetLocked(ELAPSED_REALTIME_WAKEUP, firstWakeup->GetStart().time_since_epoch());
        }
        if (firstBatch != firstWakeup) {
            auto alarmPtr = firstBatch->Get(0);
            nextNonWakeup = firstBatch->GetStart();
        }
    }

    if (nextNonWakeup != std::chrono::steady_clock::time_point::min()) {
        SetLocked(ELAPSED_REALTIME, nextNonWakeup.time_since_epoch());
    }
}

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
    TIME_HILOGI(TIME_MODULE_SERVICE, "current bootTime: %{public}lld", GetBootTimeNs().time_since_epoch().count());
    int ret = handler_->Set(static_cast<uint32_t>(type), when);
    TIME_HILOGI(TIME_MODULE_SERVICE, "Set timer to kernel. ret: %{public}d", ret);
}

void TimerManager::InsertAndBatchTimerLocked(std::shared_ptr<TimerInfo> alarm)
{
    int64_t whichBatch = (alarm->flags & static_cast<uint32_t>(STANDALONE)) ?
                         -1 :
                         AttemptCoalesceLocked(alarm->whenElapsed, alarm->maxWhenElapsed);
    TIME_HILOGI(TIME_MODULE_SERVICE, "whichBatch= %{public}" PRId64 ", id=%{public}" PRId64 "", whichBatch, alarm->id);
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
    for (const auto &alarm : triggerList) {
        if (alarm->callback) {
            TimerProxy::GetInstance().CallbackAlarmIfNeed(alarm);
        }
        if (alarm->wantAgent) {
            NotifyWantAgent(alarm->wantAgent);
        }
    }
}

void TimerManager::NotifyWantAgent(const std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "trigger wantAgent.");
    std::shared_ptr<AAFwk::Want> want = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWant(wantAgent);
    if (want == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "want is nullptr");
        return;
    }
    OHOS::AbilityRuntime::WantAgent::TriggerInfo paramsInfo("", nullptr, want, WANTAGENT_CODE_ELEVEN);
    auto code = OHOS::AbilityRuntime::WantAgent::WantAgentHelper::TriggerWantAgent(wantAgent, nullptr, paramsInfo);
    TIME_HILOGI(TIME_MODULE_SERVICE, "trigger wantAgent result: %{public}d", code);
}

void TimerManager::UpdateTimersState(std::shared_ptr<TimerInfo> &alarm)
{
    RemoveLocked(alarm->id);
    InsertAndBatchTimerLocked(alarm);
    RescheduleKernelTimerLocked();
}

bool TimerManager::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return TimerProxy::GetInstance().ProxyTimer(uid, isProxy, needRetrigger, GetBootTimeNs(),
        [this] (std::shared_ptr<TimerInfo> &alarm) { UpdateTimersState(alarm); });
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
                return alarm->UpdateWhenElapsed(GetBootTimeNs(), offset);
            }
            // 2 means the time of performing task.
            return alarm->UpdateWhenElapsed(GetBootTimeNs(), milliseconds(2));
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
        return alarm->UpdateWhenElapsed(GetBootTimeNs(), offset);
    }
}

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
    std::lock_guard<std::mutex> lock(showTimerMutex_);
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
    std::lock_guard<std::mutex> lock(showTimerMutex_);
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
    std::lock_guard<std::mutex> lock(showTimerMutex_);
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
    std::lock_guard<std::mutex> lock(showTimerMutex_);
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
    std::lock_guard<std::mutex> idleTimerLock(idleTimerMutex_);
    if (mPendingIdleUntil_ != nullptr) {
        StopTimerInner(mPendingIdleUntil_->id, true);
    }
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
            timer->wantAgent, timer->flags, true, timer->uid, timer->bundleName);
    } else {
        TimerProxy::GetInstance().RemoveUidTimerMap(timer);
    }
}

#ifdef POWER_MANAGER_ENABLE
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
        TIME_HILOGI(TIME_MODULE_SERVICE, "runningLock is not nullptr");
        runningLock_->UnLock();
        runningLock_->Lock(static_cast<int32_t>(holdLockTime / NANO_TO_MILLI));
    }
}
#endif
} // MiscServices
} // OHOS