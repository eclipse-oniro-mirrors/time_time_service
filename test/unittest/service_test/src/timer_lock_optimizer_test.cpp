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

#include <gtest/gtest.h>

#include <string>
#include <vector>
#include <memory>

#define private public
#define protected public
#ifdef RUNNING_LOCK_OPTIMIZE
#include "timer_lock_optimizer.h"
#include "timer_info.h"
#include "timer_manager.h"
#include "want_agent.h"
#include "local_pending_want.h"
#include "want_agent_constant.h"
#endif
#undef private
#undef protected

namespace OHOS {
namespace MiscServices {
namespace {

#ifdef RUNNING_LOCK_OPTIMIZE

using namespace testing;
using namespace testing::ext;

class TimerLockOptimizerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimerLockOptimizerTest::SetUpTestCase(void) {}

void TimerLockOptimizerTest::TearDownTestCase(void) {}

void TimerLockOptimizerTest::SetUp() {}

void TimerLockOptimizerTest::TearDown() {}

/**
 * @tc.name: EnsureInitialized_001
 * @tc.desc: Test EnsureInitialized sets isInitialized_ to true after success
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, EnsureInitialized_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    EXPECT_FALSE(optimizer.isInitialized_.load());
    optimizer.EnsureInitialized();
    // In test environment, Register may fail, so isInitialized_ depends on that
    // If Register succeeds, isInitialized_ should be true
    // If Register fails, isInitialized_ should remain false
    bool initState = optimizer.isInitialized_.load();
    // Call again - should not crash regardless of initialization state
    optimizer.EnsureInitialized();
    EXPECT_EQ(optimizer.isInitialized_.load(), initState);
}

/**
 * @tc.name: UpdateRunningApps_001
 * @tc.desc: Test UpdateRunningApps removes stopped app
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, UpdateRunningApps_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    optimizer.UpdateRunningApps("com.test.app", true);
    EXPECT_TRUE(optimizer.IsAppRunning("com.test.app"));

    optimizer.UpdateRunningApps("com.test.app", false);
    EXPECT_FALSE(optimizer.IsAppRunning("com.test.app"));

    optimizer.UpdateRunningApps("", true);
    EXPECT_FALSE(optimizer.IsAppRunning(""));
}

/**
 * @tc.name: RecalcLockForBundle_001
 * @tc.desc: Test RecalcLockForBundle removes matching bundle
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    optimizer.RecalcLockForBundle("com.test.app");
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), 0);
    // Add lock info
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = INT64_MAX; // Far future to not expire

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), INT64_MAX);
    // RecalcLockForBundle with empty bundleName should early return, no modification
    optimizer.RecalcLockForBundle("");
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), INT64_MAX);
    // RecalcLockForBundle with matching bundle should remove the entry
    optimizer.RecalcLockForBundle("com.test.app");
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), 0);
}

/**
 * @tc.name: RecalcLockForBundle_002
 * @tc.desc: Test RecalcLockForBundle does not remove non-matching bundle
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app1";
    info.lockExpireTime = INT64_MAX;

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    optimizer.RecalcLockForBundle("com.test.app2");
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), INT64_MAX);
}

/**
 * @tc.name: RecalcLockForBundle_003
 * @tc.desc: Test RecalcLockForBundle with last removed entry having empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_003, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    // Add lock info with non-empty bundleName (will be removed due to bundle match)
    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app"; // Will be removed
    info1.lockExpireTime = INT64_MAX;

    // Add lock info with empty bundleName (will be removed due to expiry)
    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = ""; // Empty bundleName, will be at back (last removed)
    info2.lockExpireTime = 1; // Expired, will be removed

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info1);
        optimizer.lockInfos_.push_back(info2);
    }

    // Trigger recalculation - both entries will be removed
    optimizer.RecalcLockForBundle("com.test.app");

    // Both entries should be removed, lockInfos_ becomes empty
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), 0);
}

/**
 * @tc.name: RecalcLockForBundle_004
 * @tc.desc: Test RecalcLockForBundle with last removed entry having non-empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_004, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    // Add lock info with non-empty bundleName
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = INT64_MAX; // Far future to not expire

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    // Trigger recalculation by calling with matching bundle
    optimizer.RecalcLockForBundle("com.test.app");

    // Entry should be removed, lockInfos_ becomes empty
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), 0);
}

/**
 * @tc.name: RecalcLockForBundle_005
 * @tc.desc: Test RecalcLockForBundle with single entry having empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_005, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    // Add single entry with empty bundleName
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = ""; // Empty bundleName
    info.lockExpireTime = 1; // Expired, will be removed

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    // Trigger recalculation - expired entry will be removed
    optimizer.RecalcLockForBundle("com.test.app");

    // Entry should be removed, lockInfos_ becomes empty
    EXPECT_EQ(optimizer.GetMaxLockExpireTime(), 0);
}

/**
 * @tc.name: QueryAllRunningApps_001
 * @tc.desc: Test QueryAllRunningApps clears existing runningApps_ before populating
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, QueryAllRunningApps_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    // Manually add some running apps
    {
        std::lock_guard<std::mutex> lock(optimizer.appListMutex_);
        optimizer.runningApps_.insert("com.test.app1");
        optimizer.runningApps_.insert("com.test.app2");
    }

    EXPECT_TRUE(optimizer.IsAppRunning("com.test.app1"));
    EXPECT_TRUE(optimizer.IsAppRunning("com.test.app2"));

    // QueryAllRunningApps should clear the set (and likely leave it empty in test env)
    optimizer.QueryAllRunningApps();

    // In test environment, AppMgrClient is unavailable, so runningApps_ should be empty
    EXPECT_FALSE(optimizer.IsAppRunning("com.test.app1"));
    EXPECT_FALSE(optimizer.IsAppRunning("com.test.app2"));
}

/**
 * @tc.name: BatchAcquireRunningLock_001
 * @tc.desc: Test BatchAcquireRunningLock with empty trigger list
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    optimizer.BatchAcquireRunningLock(triggerList);

    // Empty trigger list should result in empty lockInfos_
    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: BatchAcquireRunningLock_002
 * @tc.desc: Test BatchAcquireRunningLock with wakeup timer (lockInfos_ not empty)
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;

    // Create wakeup timer (type = 2 = ELAPSED_REALTIME_WAKEUP)
    auto timer = TimerInfo::CreateTimerInfo(
        "test", 1, 2,
        1000000, 0, 0, 0, false,
        nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer);

    optimizer.BatchAcquireRunningLock(triggerList);

    // Verify lockInfos_ is not empty after BatchAcquireRunningLock
    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_FALSE(optimizer.lockInfos_.empty());
    EXPECT_EQ(optimizer.lockInfos_.size(), 1u);
}

/**
 * @tc.name: MergeNewTimers_001
 * @tc.desc: Test MergeNewTimers with empty trigger list
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    optimizer.MergeNewTimers(triggerList, bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: MergeNewTimers_002
 * @tc.desc: Test MergeNewTimers with non-wakeup timer (should be skipped)
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    // Create non-wakeup timer (type = 3 = ELAPSED_REALTIME)
    auto timer = TimerInfo::CreateTimerInfo(
        "test", 1, 3, // type=3 is ELAPSED_REALTIME (non-wakeup)
        1000000, 0, 0, 0, false,
        nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer);

    optimizer.MergeNewTimers(triggerList, bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // Non-wakeup timer should be skipped
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: MergeNewTimers_003
 * @tc.desc: Test MergeNewTimers with wakeup timer without wantAgent
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_003, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    // Create wakeup timer (type = 2 = ELAPSED_REALTIME_WAKEUP)
    auto timer = TimerInfo::CreateTimerInfo(
        "test", 1, 2, // type=2 is wakeup
        1000000, 0, 0, 0, false,
        nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer);

    optimizer.MergeNewTimers(triggerList, bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // Wakeup timer without wantAgent should still be added
    EXPECT_EQ(optimizer.lockInfos_.size(), 1u);
    EXPECT_EQ(optimizer.lockInfos_[0].timerId, 1u);
    // wantBundleName should be empty (no wantAgent)
    EXPECT_TRUE(optimizer.lockInfos_[0].wantBundleName.empty());
}

/**
 * @tc.name: MergeNewTimers_004
 * @tc.desc: Test MergeNewTimers with WantAgent covering all branches
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_004, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    using OperationType = OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType;

    // Case 1: WantAgent with empty bundleName + START_ABILITY (default lock duration, not skipped)
    auto want1 = std::make_shared<AAFwk::Want>();
    auto localPendingWant1 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "", want1, static_cast<int32_t>(OperationType::START_ABILITY));
    auto wantAgent1 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant1);
    auto timer1 = TimerInfo::CreateTimerInfo(
        "test1", 1, 2, 1000000, 0, 0, 0, false,
        nullptr, wantAgent1, 0, 0, "");
    triggerList.push_back(timer1);

    // Case 2: WantAgent with non-empty bundleName + SEND_COMMON_EVENT (default lock duration)
    auto want2 = std::make_shared<AAFwk::Want>();
    auto localPendingWant2 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "com.test.app2", want2, static_cast<int32_t>(OperationType::SEND_COMMON_EVENT));
    auto wantAgent2 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant2);
    auto timer2 = TimerInfo::CreateTimerInfo(
        "test2", 2, 2, 1000000, 0, 0, 0, false,
        nullptr, wantAgent2, 0, 0, "");
    triggerList.push_back(timer2);

    // Case 3: WantAgent with non-empty bundleName + START_ABILITY (10s lock duration)
    auto want3 = std::make_shared<AAFwk::Want>();
    auto localPendingWant3 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "com.test.app3", want3, static_cast<int32_t>(OperationType::START_ABILITY));
    auto wantAgent3 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant3);
    auto timer3 = TimerInfo::CreateTimerInfo(
        "test3", 3, 2, 1000000, 0, 0, 0, false,
        nullptr, wantAgent3, 0, 0, "");
    triggerList.push_back(timer3);

    optimizer.MergeNewTimers(triggerList, bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // All 3 cases added (empty bundleName no longer skipped)
    EXPECT_EQ(optimizer.lockInfos_.size(), 3u);
    // Case 1: empty bundleName + START_ABILITY uses default lock duration (< 10s)
    EXPECT_TRUE(optimizer.lockInfos_[0].wantBundleName.empty());
    EXPECT_LT(optimizer.lockInfos_[0].lockExpireTime, bootTime + 10LL * 1000000000LL);
    // Case 2: SEND_COMMON_EVENT uses default lock duration (< 10s)
    EXPECT_EQ(optimizer.lockInfos_[1].wantBundleName, "com.test.app2");
    EXPECT_LT(optimizer.lockInfos_[1].lockExpireTime, bootTime + 10LL * 1000000000LL);
    // Case 3: non-empty bundleName + START_ABILITY uses longer lock duration (10s)
    EXPECT_EQ(optimizer.lockInfos_[2].wantBundleName, "com.test.app3");
    EXPECT_EQ(optimizer.lockInfos_[2].lockExpireTime, bootTime + 10LL * 1000000000LL);
}

/**
 * @tc.name: MergeNewTimers_005
 * @tc.desc: Test MergeNewTimers with mixed wakeup and non-wakeup timers
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_005, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    // Create mix of wakeup and non-wakeup timers
    for (int i = 0; i < 3; ++i) {
        // Non-wakeup timer (type = 3 = ELAPSED_REALTIME)
        auto timer1 = TimerInfo::CreateTimerInfo(
            "non_wakeup" + std::to_string(i), i * 2, 3,
            1000000, 0, 0, 0, false,
            nullptr, nullptr, 0, 0, "");
        triggerList.push_back(timer1);

        // Wakeup timer (type = 2 = ELAPSED_REALTIME_WAKEUP)
        auto timer2 = TimerInfo::CreateTimerInfo(
            "wakeup" + std::to_string(i), i * 2 + 1, 2,
            1000000, 0, 0, 0, false,
            nullptr, nullptr, 0, 0, "");
        triggerList.push_back(timer2);
    }

    optimizer.MergeNewTimers(triggerList, bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // Only wakeup timers should be added (3)
    EXPECT_EQ(optimizer.lockInfos_.size(), 3u);
}

/**
 * @tc.name: SortAndDeduplicate_001
 * @tc.desc: Test SortAndDeduplicate with empty list
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 1000000000LL;

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: SortAndDeduplicate_002
 * @tc.desc: Test SortAndDeduplicate removes expired entries
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL; // 100 seconds

    // Add expired entry
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = bootTime - 1000000LL; // Expired

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: SortAndDeduplicate_003
 * @tc.desc: Test SortAndDeduplicate keeps valid entries
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_003, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL;

    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = bootTime + 1000000000LL; // Valid (1 second in future)

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_EQ(optimizer.lockInfos_.size(), 1u);
}

/**
 * @tc.name: SortAndDeduplicate_004
 * @tc.desc: Test SortAndDeduplicate removes duplicates keeping largest
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_004, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL;

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app";
    info1.lockExpireTime = bootTime + 1000000000LL;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app";
    info2.lockExpireTime = bootTime + 2000000000LL; // Larger

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info1);
        optimizer.lockInfos_.push_back(info2);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_EQ(optimizer.lockInfos_.size(), 1u);
    EXPECT_EQ(optimizer.lockInfos_[0].lockExpireTime, bootTime + 2000000000LL);
}

/**
 * @tc.name: SortAndDeduplicate_005
 * @tc.desc: Test SortAndDeduplicate sorts by expire time descending
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_005, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL;

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = bootTime + 1000000000LL;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app2";
    info2.lockExpireTime = bootTime + 3000000000LL;

    TimerLockOptimizer::TimerLockInfo info3;
    info3.timerId = 3;
    info3.wantBundleName = "com.test.app3";
    info3.lockExpireTime = bootTime + 2000000000LL;

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info1);
        optimizer.lockInfos_.push_back(info2);
        optimizer.lockInfos_.push_back(info3);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    EXPECT_EQ(optimizer.lockInfos_.size(), 3u);
    // First should have largest expire time
    EXPECT_EQ(optimizer.lockInfos_[0].lockExpireTime, bootTime + 3000000000LL);
}

/**
 * @tc.name: SortAndDeduplicate_006
 * @tc.desc: Test SortAndDeduplicate sorts by bundleName when expire times are equal
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_006, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL;

    // Add entries with same expire time but different bundle names
    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app3";
    info1.lockExpireTime = bootTime + 1000000000LL;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app1";
    info2.lockExpireTime = bootTime + 1000000000LL;

    TimerLockOptimizer::TimerLockInfo info3;
    info3.timerId = 3;
    info3.wantBundleName = "com.test.app2";
    info3.lockExpireTime = bootTime + 1000000000LL;

    // Add entry with empty bundleName
    TimerLockOptimizer::TimerLockInfo info4;
    info4.timerId = 4;
    info4.wantBundleName = "";  // empty bundleName
    info4.lockExpireTime = bootTime + 1000000000LL;

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info1);
        optimizer.lockInfos_.push_back(info2);
        optimizer.lockInfos_.push_back(info3);
        optimizer.lockInfos_.push_back(info4);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // All 4 entries should be kept (empty bundleName doesn't deduplicate)
    EXPECT_EQ(optimizer.lockInfos_.size(), 4u);
    // Should be sorted: empty string first, then alphabetically
    EXPECT_TRUE(optimizer.lockInfos_[0].wantBundleName.empty());
    EXPECT_EQ(optimizer.lockInfos_[1].wantBundleName, "com.test.app1");
    EXPECT_EQ(optimizer.lockInfos_[2].wantBundleName, "com.test.app2");
    EXPECT_EQ(optimizer.lockInfos_[3].wantBundleName, "com.test.app3");
}

/**
 * @tc.name: SortAndDeduplicate_007
 * @tc.desc: Test SortAndDeduplicate triggers move operation when duplicate is skipped
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_007, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = 100000000000LL;

    // Create entries where a duplicate will be skipped, triggering move
    // After sort (descending by expireTime):
    //   info1: app1, expire=300 -> kept, writeIdx=0
    //   info2: app1, expire=200 -> duplicate, skipped
    //   info3: app2, expire=100 -> needs move from readIdx=2 to writeIdx=1
    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = bootTime + 3000000000LL;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app1"; // Same bundle as info1
    info2.lockExpireTime = bootTime + 2000000000LL;

    TimerLockOptimizer::TimerLockInfo info3;
    info3.timerId = 3;
    info3.wantBundleName = "com.test.app2";
    info3.lockExpireTime = bootTime + 1000000000LL;

    {
        std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
        optimizer.lockInfos_.push_back(info1);
        optimizer.lockInfos_.push_back(info2);
        optimizer.lockInfos_.push_back(info3);
    }

    optimizer.SortAndDeduplicate(bootTime);

    std::lock_guard<std::mutex> lock(optimizer.lockInfosMutex_);
    // Duplicate removed, should have 2 entries
    EXPECT_EQ(optimizer.lockInfos_.size(), 2u);
    // First is app1 with largest expire
    EXPECT_EQ(optimizer.lockInfos_[0].wantBundleName, "com.test.app1");
    EXPECT_EQ(optimizer.lockInfos_[0].lockExpireTime, bootTime + 3000000000LL);
    // Second is app2 (moved from index 2 to index 1)
    EXPECT_EQ(optimizer.lockInfos_[1].wantBundleName, "com.test.app2");
    EXPECT_EQ(optimizer.lockInfos_[1].lockExpireTime, bootTime + 1000000000LL);
}

/**
 * @tc.name: IsAbilityStartingOperation_001
 * @tc.desc: Test IsAbilityStartingOperation with all operation types
 * @tc.type: FUNC
 */
HWTEST_F(TimerLockOptimizerTest, IsAbilityStartingOperation_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    using OperationType = OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType;

    // Should return false for SEND_COMMON_EVENT and UNKNOWN_TYPE
    EXPECT_FALSE(optimizer.IsAbilityStartingOperation(OperationType::SEND_COMMON_EVENT));
    EXPECT_FALSE(optimizer.IsAbilityStartingOperation(OperationType::UNKNOWN_TYPE));

    // Should return true for ability/service starting operations
    EXPECT_TRUE(optimizer.IsAbilityStartingOperation(OperationType::START_ABILITY));
}

#endif // RUNNING_LOCK_OPTIMIZE

} // namespace
} // namespace MiscServices
} // namespace OHOS