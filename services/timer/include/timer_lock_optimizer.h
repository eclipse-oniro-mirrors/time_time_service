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
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

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

    // Initialize app state observer and query current running apps
    void Init();

    // Ensure initialized (lazy initialization)
    void EnsureInitialized();

    // Update app running state and recalculate lock time if needed
    void UpdateRunningApps(const std::string& bundleName, bool isRunning);

    // Batch process triggered timers and acquire a single running lock
    // until the maximum expiration time among all timers
    void BatchAcquireRunningLock(const std::vector<std::shared_ptr<TimerInfo>>& triggerList);

    // Check if app is currently running
    bool IsAppRunning(const std::string& bundleName);

    // Recalculate lock time when app starts or notification fails
    void RecalcLockForBundle(const std::string& bundleName);

    // Get the maximum lock expiration time from lockInfos_
    // Returns 0 if lockInfos_ is empty
    int64_t GetMaxLockExpireTime();

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

    // Check if the operation type requires ability start (needs longer lock duration)
    bool IsAbilityStartingOperation(WantAgentConstant::OperationType operType);

    TimerManager* const manager_;

    // Initialization flag for lazy initialization
    std::atomic<bool> isInitialized_{false};

    // Running apps tracking
    std::set<std::string> runningApps_;
    std::mutex appListMutex_;

    // Lock info collection
    std::vector<TimerLockInfo> lockInfos_;
    std::mutex lockInfosMutex_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // RUNNING_LOCK_OPTIMIZE

#endif // TIMER_LOCK_OPTIMIZER_H
