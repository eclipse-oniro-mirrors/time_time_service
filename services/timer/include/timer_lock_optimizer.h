/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef TIMER_LOCK_OPTIMIZER_H
#define TIMER_LOCK_OPTIMIZER_H

#ifdef RUNNING_LOCK_OPTIMIZE

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "want_agent.h"
#include "want_agent_constant.h"

namespace OHOS {
namespace MiscServices {

using namespace OHOS::AbilityRuntime::WantAgent;

class TimerInfo;
class TimerManager;

// Timer lock optimization module for managing running lock duration
// based on app state and timer characteristics
class TimerLockOptimizer : public std::enable_shared_from_this<TimerLockOptimizer> {
public:
    explicit TimerLockOptimizer(TimerManager* manager);
    ~TimerLockOptimizer() = default;

    // Check if the operation type requires ability start (needs longer lock duration)
    bool IsAbilityStartingOperation(WantAgentConstant::OperationType operType);

    // Initialize app state observer and query current running apps
    void Init();

    // Update app running state and recalculate lock time if needed
    void UpdateRunningApps(const std::string& bundleName, bool isRunning);

    // Batch process triggered timers and acquire a single running lock
    // until the maximum expiration time among all timers
    void BatchAcquireRunningLock(const std::vector<std::shared_ptr<TimerInfo>>& triggerList);

    // Check if app is currently running
    bool IsAppRunning(const std::string& bundleName);

    // Recalculate lock time when app starts or notification fails
    void RecalcLockForBundle(const std::string& bundleName);

    // Get current timer lock expire time
    int64_t GetTimerLockExpireTime() const { return timerLockExpireTime_.load(); }

    // Get bundleName from cache by timerId (returns empty string if not found)
    std::string GetBundleNameFromCache(uint64_t timerId) { return targetBundleNameCache_[timerId]; }

    // Clear bundleName cache after timer delivery completes
    void ClearBundleNameCache() { targetBundleNameCache_.clear(); }

private:
    struct TimerLockInfo {
        uint64_t timerId;
        std::string wantBundleName;
        int64_t lockExpireTime;
    };

    void QueryAllRunningApps();

    // Helper functions for lock management
    void MergeNewTimers(const std::vector<std::shared_ptr<TimerInfo>>& triggerList, int64_t bootTime);
    void SortAndDeduplicate(int64_t bootTime);

    // Internal helper to acquire running lock with max expire time comparison
    void AcquireRunningLockInternal(int64_t expireTime, int64_t bootTime);

    // Extract bundleName from WantAgent
    // Returns empty string if want is null or not ability-starting operation
    std::string ExtractBundleNameFromWantAgent(const std::shared_ptr<WantAgent>& wantAgent);

    // Get target bundleName from WantAgent (the app to be started, not the creator)
    // Returns empty string for non-ability-starting operations (SEND_COMMON_EVENT, UNKNOWN_TYPE)
    // When want == nullptr (multi-user scenario), attempts to get want from database
    std::string GetTargetBundleName(const std::shared_ptr<TimerInfo>& timer);

    // Get target bundleName in multi-user scenario when want == nullptr
    // Retrieves want from database and extracts bundleName
    // Returns empty string if failed to retrieve
    std::string GetBundleNameMultiUser(const std::shared_ptr<TimerInfo>& timer);

    // Raw pointer is safe by the singleton contract: TimerManager::GetInstance() publishes
    // an instance that is never destroyed for the lifetime of the process (see the
    // publish-then-store comment in TimerManager::GetInstance), and this optimizer is owned
    // by that singleton (lockOptimizer_), so manager_ always outlives this object.
    TimerManager* const manager_;

    // Initialization flag
    std::atomic<bool> isInitialized_{false};

    // Running apps tracking
    std::set<std::string> runningApps_;
    std::mutex appListMutex_;

    // Lock info collection
    std::vector<TimerLockInfo> lockInfos_;
    std::mutex lockInfosMutex_;

    // Max timer lock expire time (nanoseconds since boot)
    std::atomic<int64_t> timerLockExpireTime_{0};

    // Cache for target bundleName from WantAgent (timerId -> targetBundleName)
    // Read/write operations are performed in the same thread (TimerLooper thread)
    // No concurrent access scenarios, no lock required
    std::map<uint64_t, std::string> targetBundleNameCache_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // RUNNING_LOCK_OPTIMIZE

#endif // TIMER_LOCK_OPTIMIZER_H
