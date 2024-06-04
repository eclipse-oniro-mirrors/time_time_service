/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef TIMER_MANAGER_H
#define TIMER_MANAGER_H

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <thread>
#include <vector>
#include <unordered_set>

#include "batch.h"
#include "timer_handler.h"
#include "want_agent_helper.h"
#include "time_common.h"

#ifdef POWER_MANAGER_ENABLE
#include "completed_callback.h"
#include "power_mgr_client.h"
#endif

namespace OHOS {
namespace MiscServices {
constexpr const char *NEED_RECOVER_ON_REBOOT = "not_support";

class TimerManager : public ITimerManager {
public:
    static std::shared_ptr<TimerManager> Create();
    int32_t CreateTimer(TimerPara &paras,
                        std::function<void (const uint64_t)> callback,
                        std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                        int uid,
                        int pid,
                        uint64_t &timerId,
                        DatabaseType type) override;
    void ReCreateTimer(uint64_t timerId, std::shared_ptr<TimerEntry> timerInfo);
    int32_t StartTimer(uint64_t timerId, uint64_t triggerTime) override;
    int32_t StopTimer(uint64_t timerId) override;
    int32_t DestroyTimer(uint64_t timerId) override;
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger) override;
    bool ProxyTimer(std::set<int> pidList, bool isProxy, bool needRetrigger) override;
    bool AdjustTimer(bool isAdjust, uint32_t interval) override;
    void SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption) override;
    bool ResetAllProxy() override;
    bool ShowTimerEntryMap(int fd);
    bool ShowTimerEntryById(int fd, uint64_t timerId);
    bool ShowTimerTriggerById(int fd, uint64_t timerId);
    bool ShowIdleTimerInfo(int fd);
    ~TimerManager() override;
    void HandleRSSDeath();

private:
    explicit TimerManager(std::shared_ptr<TimerHandler> impl);
    void TimerLooper();

    void SetHandler(uint64_t id,
                    int type,
                    uint64_t triggerAtTime,
                    uint64_t windowLength,
                    uint64_t interval,
                    int flag,
                    std::function<void (const uint64_t)> callback,
                    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
                    int uid,
                    int pid,
                    const std::string &bundleName);
    void SetHandlerLocked(uint64_t id,
                          int type,
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
                          const std::string &bundleName);
    void RemoveHandler(uint64_t id);
    void RemoveLocked(uint64_t id, bool needReschedule);
    void ReBatchAllTimers();
    void ReAddTimerLocked(std::shared_ptr<TimerInfo> timer,
                          std::chrono::steady_clock::time_point nowElapsed);
    void ReCalcuOriWhenElapsed(std::shared_ptr<TimerInfo> timer,
                          std::chrono::steady_clock::time_point nowElapsed);
    void SetHandlerLocked(std::shared_ptr<TimerInfo> alarm, bool rebatching, bool isRebatched);
    void InsertAndBatchTimerLocked(std::shared_ptr<TimerInfo> alarm);
    int64_t AttemptCoalesceLocked(std::chrono::steady_clock::time_point whenElapsed,
                                  std::chrono::steady_clock::time_point maxWhen);
    void TriggerIdleTimer();
    void ProcTriggerTimer(std::shared_ptr<TimerInfo> &alarm,
        std::vector<std::shared_ptr<TimerInfo>> &triggerList, const std::chrono::steady_clock::time_point &nowElapsed);
    bool TriggerTimersLocked(std::vector<std::shared_ptr<TimerInfo>> &triggerList,
                             std::chrono::steady_clock::time_point nowElapsed);
    void RescheduleKernelTimerLocked();
    void DeliverTimersLocked(const std::vector<std::shared_ptr<TimerInfo>> &triggerList);
    std::shared_ptr<Batch> FindFirstWakeupBatchLocked();
    void SetLocked(int type, std::chrono::nanoseconds when);
    std::chrono::steady_clock::time_point ConvertToElapsed(std::chrono::milliseconds when, int type);
    std::chrono::steady_clock::time_point GetBootTimeNs();
    int32_t StopTimerInner(uint64_t timerNumber, bool needDestroy);
    bool NotifyWantAgent(const std::shared_ptr<TimerInfo> &timer);
    bool CheckAllowWhileIdle(const std::shared_ptr<TimerInfo> &alarm);
    bool AdjustDeliveryTimeBasedOnDeviceIdle(const std::shared_ptr<TimerInfo> &alarm);
    bool AdjustTimersBasedOnDeviceIdle();
    void HandleRepeatTimer(const std::shared_ptr<TimerInfo> &timer, std::chrono::steady_clock::time_point nowElapsed);
    #ifdef POWER_MANAGER_ENABLE
    void HandleRunningLock(const std::shared_ptr<Batch> &firstWakeup);
    void AddRunningLock(long long holdLockTime);
    #endif

    void UpdateTimersState(std::shared_ptr<TimerInfo> &alarm);
    bool AdjustSingleTimer(std::shared_ptr<TimerInfo> timer);

    std::map<uint64_t, std::shared_ptr<TimerEntry>> timerEntryMap_;
    std::default_random_engine random_;
    std::atomic_bool runFlag_;
    std::shared_ptr<TimerHandler> handler_;
    std::unique_ptr<std::thread> alarmThread_;
    std::vector<std::shared_ptr<Batch>> alarmBatches_;
    std::mutex mutex_;
    std::mutex entryMapMutex_;
    std::chrono::system_clock::time_point lastTimeChangeClockTime_;
    std::chrono::steady_clock::time_point lastTimeChangeRealtime_;

    std::vector<std::shared_ptr<TimerInfo>> pendingDelayTimers_;
    // map<timerId, original trigger time> for delayed timers
    std::map<uint64_t, std::chrono::steady_clock::time_point> delayedTimers_;
    // idle timer
    std::shared_ptr<TimerInfo> mPendingIdleUntil_;
    bool adjustPolicy_ = false;
    uint32_t adjustInterval_ = 0;
    #ifdef POWER_MANAGER_ENABLE
    std::shared_ptr<PowerMgr::RunningLock> runningLock_;
    int64_t lockExpiredTime_ = 0;
    #endif
}; // timer_manager
} // MiscServices
} // OHOS

#endif