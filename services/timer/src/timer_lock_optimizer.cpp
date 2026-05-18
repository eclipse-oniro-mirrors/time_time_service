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

#include "timer_lock_optimizer.h"

#ifdef RUNNING_LOCK_OPTIMIZE

#include <cinttypes>
#include <unordered_set>

#include "ability_state_data.h"
#include "app_mgr_client.h"
#include "running_process_info.h"
#include "singleton.h"
#include "time_hilog.h"
#include "timer_app_state_observer.h"
#include "timer_info.h"
#include "timer_manager.h"
#include "want_agent_helper.h"

namespace OHOS {
namespace MiscServices {

// Lock duration for timers that start apps (10 seconds in nanoseconds)
// Empirically determined to be sufficient for app cold start
// without holding the lock longer than necessary.
constexpr int64_t APP_START_RUNNING_LOCK_DURATION_NS = 10LL * 1000000000LL;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime::WantAgent;

// =============================================================================
// Section 1: Constructor / Initialization
// =============================================================================

TimerLockOptimizer::TimerLockOptimizer(TimerManager* manager) : manager_(manager) {}

void TimerLockOptimizer::Init()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Running lock optimize enable, start init TimerLockOptimizer");
    if (isInitialized_.load()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "TimerLockOptimizer already initialized");
        return;
    }
    std::weak_ptr<TimerLockOptimizer> weakThis = weak_from_this();
    bool registerResult = TimerAppStateObserver::GetInstance()->Register({},
        [weakThis = std::move(weakThis)](const std::string &name, bool isRunning) {
            if (auto sharedThis = weakThis.lock()) {
                sharedThis->UpdateRunningApps(name, isRunning);
            }
        });
    if (!registerResult) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Register app state observer failed");
        return;
    }
    QueryAllRunningApps();
    isInitialized_.store(true);
    TIME_HILOGI(TIME_MODULE_SERVICE, "Init TimerLockOptimizer end");
}

void TimerLockOptimizer::QueryAllRunningApps()
{
    auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
    if (appMgrClient == nullptr) {
        return;
    }
    std::vector<RunningProcessInfo> runningProcesses;
    if (appMgrClient->GetAllRunningProcesses(runningProcesses) !=
        AppMgrResultCode::RESULT_OK) {
        return;
    }
    std::lock_guard<std::mutex> lock(appListMutex_);
    runningApps_.clear();
    for (const auto &process : runningProcesses) {
        for (const auto &bundleName : process.bundleNames) {
            if (!bundleName.empty()) {
                runningApps_.insert(bundleName);
            }
        }
    }
    TIME_HILOGI(TIME_MODULE_SERVICE,
                "Queried %{public}zu running apps",
                runningApps_.size());
}

// =============================================================================
// Section 2: Public API
// =============================================================================

std::string TimerLockOptimizer::ExtractBundleNameFromWantAgent(const std::shared_ptr<WantAgent>& wantAgent)
{
    auto want = WantAgentHelper::GetWant(wantAgent);
    if (want == nullptr) {
        return "";
    }
    if (!IsAbilityStartingOperation(WantAgentHelper::GetType(wantAgent))) {
        return "";
    }
    return want->GetElement().GetBundleName();
}

// Get target bundleName from WantAgent (the app to be started, not the creator)
// Returns empty string for non-ability-starting operations (SEND_COMMON_EVENT, UNKNOWN_TYPE)
// When want == nullptr (multi-user scenario), attempts to get want from database
std::string TimerLockOptimizer::GetTargetBundleName(const std::shared_ptr<TimerInfo>& timer)
{
    if (timer == nullptr) {
        return "";
    }
    auto want = WantAgentHelper::GetWant(timer->wantAgent);
    if (want != nullptr) {
        return ExtractBundleNameFromWantAgent(timer->wantAgent);
    }
    // want == nullptr: multi-user scenario, get bundleName from database
    return GetBundleNameMultiUser(timer);
}

std::string TimerLockOptimizer::GetBundleNameMultiUser(const std::shared_ptr<TimerInfo>& timer)
{
    if (manager_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "manager_ is nullptr");
        return "";
    }
    #ifdef MULTI_ACCOUNT_ENABLE
    if (manager_->CheckUserIdForNotify(timer) != E_TIME_OK) {
        return "";
    }
    #endif
    auto wantStr = manager_->GetWantString(timer->id);
    if (wantStr.empty()) {
        return "";
    }
    auto newWantAgent = WantAgentHelper::FromString(wantStr);
    return ExtractBundleNameFromWantAgent(newWantAgent);
}

void TimerLockOptimizer::BatchAcquireRunningLock(
    const std::vector<std::shared_ptr<TimerInfo>> &triggerList)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();

    // Merge new timer information, sorts by expiration time,
    // and removes duplicates and expired entries to optimize running lock duration.
    MergeNewTimers(triggerList, bootTime);
    SortAndDeduplicate(bootTime);

    int64_t maxExpireTime = 0;
    std::string bundleName;
    {
        std::lock_guard<std::mutex> lock(lockInfosMutex_);
        if (!lockInfos_.empty()) {
            maxExpireTime = lockInfos_.front().lockExpireTime;
            bundleName = lockInfos_.front().wantBundleName;
        }
    }

    if (maxExpireTime > 0) {
        TIME_HILOGD(TIME_MODULE_SERVICE,
                    "BatchAcquireRunningLock: maxExpireTime=%{public}" PRId64 ",bundleName=%{public}s",
                    maxExpireTime, bundleName.c_str());
        AcquireRunningLockInternal(maxExpireTime, bootTime);
    }
}

bool TimerLockOptimizer::IsAppRunning(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(appListMutex_);
    return runningApps_.find(bundleName) != runningApps_.end();
}

void TimerLockOptimizer::UpdateRunningApps(const std::string &bundleName, bool isRunning)
{
    TIME_HILOGD(
        TIME_MODULE_SERVICE,
        "UpdateRunningApps: bundleName=%{public}s, isRunning=%{public}d",
        bundleName.c_str(), isRunning);
    if (bundleName.empty()) {
        return;
    }
    if (isRunning) {
        {
            std::lock_guard<std::mutex> lock(appListMutex_);
            runningApps_.insert(bundleName);
        }
        RecalcLockForBundle(bundleName);
    } else {
        std::lock_guard<std::mutex> lock(appListMutex_);
        runningApps_.erase(bundleName);
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "runningApps_ size=%{public}zu", runningApps_.size());
}

void TimerLockOptimizer::RecalcLockForBundle(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return;
    }
    int64_t currentBootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t newMaxExpireTime = 0;
    bool hasNonEmptyBundleName = false;
    {
        std::lock_guard<std::mutex> lock(lockInfosMutex_);
        // If lockInfos_ is empty, no need to recalculate
        if (lockInfos_.empty()) {
            return;
        }

        // Remove entries for the specified bundle and expired entries
        auto it = std::remove_if(lockInfos_.begin(), lockInfos_.end(),
            [&bundleName, currentBootTime, &hasNonEmptyBundleName](const TimerLockInfo &info) {
                if (info.wantBundleName == bundleName || info.lockExpireTime < currentBootTime) {
                    if (!info.wantBundleName.empty()) {
                        hasNonEmptyBundleName = true;
                    }
                    return true;
                }
                return false;
            });
        // If nothing was removed, no need to recalculate
        if (it == lockInfos_.end()) {
            return;
        }
        lockInfos_.erase(it, lockInfos_.end());

        if (!lockInfos_.empty()) {
            newMaxExpireTime = lockInfos_.front().lockExpireTime;
        }
        if (hasNonEmptyBundleName) {
            // If start ability type lock info was removed, add extra 1s lock duration
            int64_t additionalExpireTime = currentBootTime + TimerManager::GetDefaultRunningLockDuration();
            newMaxExpireTime = std::max(newMaxExpireTime, additionalExpireTime);
        }
    }
    AcquireRunningLockInternal(newMaxExpireTime, currentBootTime);
}

// =============================================================================
// Section 3: Private Helper Methods
// =============================================================================

void TimerLockOptimizer::AcquireRunningLockInternal(int64_t expireTime, int64_t bootTime)
{
    if (manager_ == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "AcquireRunningLockInternal: manager_ is nullptr");
        return;
    }
    if (expireTime <= manager_->lockExpiredTime_.load()) {
        TIME_HILOGD(TIME_MODULE_SERVICE,
                    "AcquireRunningLockInternal: expireTime=%{public}" PRId64 " <= lockExpiredTime=%{public}" PRId64,
                    expireTime, manager_->lockExpiredTime_.load());
        manager_->AddRunningLock(manager_->lockExpiredTime_.load() - bootTime);
        return;
    }
    timerLockExpireTime_.store(expireTime);
    manager_->AddRunningLock(expireTime - bootTime);
}

bool TimerLockOptimizer::IsAbilityStartingOperation(WantAgentConstant::OperationType operType)
{
    return operType != WantAgentConstant::OperationType::SEND_COMMON_EVENT &&
           operType != WantAgentConstant::OperationType::UNKNOWN_TYPE;
}

void TimerLockOptimizer::MergeNewTimers(
    const std::vector<std::shared_ptr<TimerInfo>> &triggerList,
    int64_t bootTime)
{
    // Phase 1: Collect timer data (IPC calls, no lock)
    std::vector<TimerLockInfo> newTimers;
    newTimers.reserve(triggerList.size());
    for (const auto &timer : triggerList) {
        if (!timer->wakeup) {
            continue;
        }

        TimerLockInfo newInfo;
        newInfo.timerId = timer->id;
        int64_t lockDuration = TimerManager::GetDefaultRunningLockDuration();

        if (timer->wantAgent) {
            auto wantBundleName = GetTargetBundleName(timer);
            // Apply longer lock duration for non-empty bundle name (ability-starting operations)
            if (!wantBundleName.empty()) {
                newInfo.wantBundleName = wantBundleName;
                lockDuration = APP_START_RUNNING_LOCK_DURATION_NS;
                targetBundleNameCache_[timer->id] = wantBundleName;
            }
        }

        newInfo.lockExpireTime = bootTime + lockDuration;
        newTimers.push_back(newInfo);
    }

    // Phase 2: Merge into lockInfos_ (with lock)
    {
        std::lock_guard<std::mutex> lock(lockInfosMutex_);
        lockInfos_.insert(lockInfos_.end(), newTimers.begin(), newTimers.end());
    }
}

void TimerLockOptimizer::SortAndDeduplicate(int64_t bootTime)
{
    std::lock_guard<std::mutex> lock(lockInfosMutex_);
    // Sort by lockExpireTime descending (largest first), then by bundleName for dedup stability.
    // Descending order ensures that when we deduplicate by bundle name, we keep the entry
    // with the largest expiration time for each bundle.
    std::sort(lockInfos_.begin(), lockInfos_.end(),
        [](const TimerLockInfo &a, const TimerLockInfo &b) {
            if (a.lockExpireTime != b.lockExpireTime) {
                return a.lockExpireTime > b.lockExpireTime;
            }
            return a.wantBundleName < b.wantBundleName;
        });

    // Single pass - filter expired and deduplicate by bundle
    std::unordered_set<std::string> seenBundles;
    size_t writeIdx = 0;
    for (size_t readIdx = 0; readIdx < lockInfos_.size(); ++readIdx) {
        const auto &info = lockInfos_[readIdx];
        // Skip expired entries
        if (info.lockExpireTime < bootTime) {
            continue;
        }
        // Skip duplicate bundle (keep first = largest expire time due to sort
        // order)
        if (!info.wantBundleName.empty()) {
            if (seenBundles.find(info.wantBundleName) != seenBundles.end()) {
                continue;
            }
            seenBundles.insert(info.wantBundleName);
        }
        // Keep this entry
        if (writeIdx != readIdx) {
            lockInfos_[writeIdx] = std::move(lockInfos_[readIdx]);
        }
        ++writeIdx;
    }
    lockInfos_.resize(writeIdx);
}

} // namespace MiscServices
} // namespace OHOS

#endif // RUNNING_LOCK_OPTIMIZE
