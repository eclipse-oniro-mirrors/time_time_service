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
#include "time_common.h"
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

constexpr int64_t APP_START_RUNNING_LOCK_DURATION_NS = 10LL * 1000000000LL;

class TimerLockOptimizerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static TimerManager* timerManager_;
    static std::shared_ptr<TimerLockOptimizer> lockOptimizer_;
};

TimerManager* TimerLockOptimizerTest::timerManager_ = nullptr;
std::shared_ptr<TimerLockOptimizer> TimerLockOptimizerTest::lockOptimizer_ = nullptr;

void TimerLockOptimizerTest::SetUpTestCase(void)
{
    timerManager_ = TimerManager::GetInstance();
    // Create lockOptimizer with shared_ptr for enable_shared_from_this to work correctly
    // Use timerManager_ if available, otherwise nullptr (tests will cover nullptr branches)
    lockOptimizer_ = std::make_shared<TimerLockOptimizer>(timerManager_);
    if (timerManager_ != nullptr) {
        lockOptimizer_->Init();
    }
}

void TimerLockOptimizerTest::TearDownTestCase(void)
{
    lockOptimizer_.reset();
}

void TimerLockOptimizerTest::SetUp() {}

void TimerLockOptimizerTest::TearDown() {}

// =============================================================================
// Init Tests
// =============================================================================

/**
 * @tc.name: Init_001
 * @tc.desc: Test Init returns early when already initialized
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, Init_001, TestSize.Level1)
{
    lockOptimizer_->isInitialized_.store(true);
    lockOptimizer_->Init();
    EXPECT_TRUE(lockOptimizer_->isInitialized_.load());
}

// =============================================================================
// ExtractBundleNameFromWantAgent Tests
// =============================================================================

/**
 * @tc.name: ExtractBundleNameFromWantAgent_001
 * @tc.desc: Test ExtractBundleNameFromWantAgent with nullptr wantAgent and non-ability-starting operation
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, ExtractBundleNameFromWantAgent_001, TestSize.Level1)
{
    // Branch: wantAgent == nullptr, GetWant returns nullptr
    EXPECT_TRUE(lockOptimizer_->ExtractBundleNameFromWantAgent(nullptr).empty());

    // Branch: SEND_COMMON_EVENT (non-ability-starting), returns empty
    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName("com.target.app", "Ability");
    auto localPendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want, static_cast<int32_t>(
            OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT));
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    EXPECT_TRUE(lockOptimizer_->ExtractBundleNameFromWantAgent(wantAgent).empty());
}

/**
 * @tc.name: ExtractBundleNameFromWantAgent_002
 * @tc.desc: Test ExtractBundleNameFromWantAgent with ability-starting operation
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, ExtractBundleNameFromWantAgent_002, TestSize.Level1)
{
    // Branch: START_ABILITY (ability-starting), returns bundleName
    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName("com.target.app", "Ability");
    auto localPendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want, static_cast<int32_t>(
            OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY));
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    EXPECT_EQ(lockOptimizer_->ExtractBundleNameFromWantAgent(wantAgent), "com.target.app");
}

/**
 * @tc.name: ExtractBundleNameFromWantAgent_003
 * @tc.desc: Test ExtractBundleNameFromWantAgent with empty bundleName
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, ExtractBundleNameFromWantAgent_003, TestSize.Level1)
{
    // Branch: START_ABILITY with empty bundleName in want
    auto want = std::make_shared<AAFwk::Want>();
    // Not setting ElementName, bundleName will be empty
    auto localPendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want, static_cast<int32_t>(
            OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY));
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    EXPECT_TRUE(lockOptimizer_->ExtractBundleNameFromWantAgent(wantAgent).empty());
}

// =============================================================================
// GetTargetBundleName Tests
// =============================================================================

/**
 * @tc.name: GetTargetBundleName_001
 * @tc.desc: Test GetTargetBundleName with nullptr timer and non-ability-starting operation
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, GetTargetBundleName_001, TestSize.Level1)
{
    // Branch: timer == nullptr
    EXPECT_TRUE(lockOptimizer_->GetTargetBundleName(nullptr).empty());

    // Branch: SEND_COMMON_EVENT (non-ability-starting), returns empty even with bundleName
    auto want1 = std::make_shared<AAFwk::Want>();
    want1->SetElementName("com.target.app", "Ability");
    auto localPendingWant1 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want1, static_cast<int32_t>(
            OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType::SEND_COMMON_EVENT));
    auto wantAgent1 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant1);
    auto timer1 = TimerInfo::CreateTimerInfo("test", 1, 1, 0, 0, 0, 0, false,
        nullptr, wantAgent1, 0, 0, "com.creator.app");
    EXPECT_TRUE(lockOptimizer_->GetTargetBundleName(timer1).empty());
}

/**
 * @tc.name: GetTargetBundleName_002
 * @tc.desc: Test GetTargetBundleName with ability-starting operation and want != nullptr
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, GetTargetBundleName_002, TestSize.Level1)
{
    // Branch: START_ABILITY (ability-starting) with want != nullptr, returns bundleName
    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName("com.target.app", "Ability");
    auto localPendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want, static_cast<int32_t>(
            OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY));
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    auto timer = TimerInfo::CreateTimerInfo("test", 2, 1, 0, 0, 0, 0, false,
        nullptr, wantAgent, 0, 0, "com.creator.app");
    EXPECT_EQ(lockOptimizer_->GetTargetBundleName(timer), "com.target.app");
}

// =============================================================================
// GetBundleNameMultiUser Tests
// =============================================================================

/**
 * @tc.name: GetBundleNameMultiUser_001
 * @tc.desc: Test GetBundleNameMultiUser with manager_ == nullptr
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, GetBundleNameMultiUser_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    auto timer = TimerInfo::CreateTimerInfo("test", 1, 1, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "");
    EXPECT_TRUE(optimizer.GetBundleNameMultiUser(timer).empty());
}

/**
 * @tc.name: GetBundleNameMultiUser_002
 * @tc.desc: Test GetBundleNameMultiUser with manager_ != nullptr (database query returns empty)
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, GetBundleNameMultiUser_002, TestSize.Level1)
{
    // manager_ != nullptr, but database has no data, GetWantString returns empty
    auto timer = TimerInfo::CreateTimerInfo("test", 1, 1, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "");
    EXPECT_TRUE(lockOptimizer_->GetBundleNameMultiUser(timer).empty());
}

// =============================================================================
// UpdateRunningApps Tests
// =============================================================================

/**
 * @tc.name: UpdateRunningApps_001
 * @tc.desc: Test UpdateRunningApps with isRunning true/false and empty bundleName
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, UpdateRunningApps_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);

    // Branch: isRunning = true
    optimizer.UpdateRunningApps("com.test.app", true);
    EXPECT_TRUE(optimizer.IsAppRunning("com.test.app"));

    // Branch: isRunning = false
    optimizer.UpdateRunningApps("com.test.app", false);
    EXPECT_FALSE(optimizer.IsAppRunning("com.test.app"));

    // Branch: empty bundleName
    optimizer.UpdateRunningApps("", true);
    EXPECT_FALSE(optimizer.IsAppRunning(""));
}

/**
 * @tc.name: UpdateRunningApps_002
 * @tc.desc: Test UpdateRunningApps with isRunning false does not trigger RecalcLockForBundle
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, UpdateRunningApps_002, TestSize.Level1)
{
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = INT64_MAX;

    lockOptimizer_->lockInfos_.push_back(info);

    // isRunning = false should not call RecalcLockForBundle
    lockOptimizer_->UpdateRunningApps("com.test.app", false);
    EXPECT_EQ(lockOptimizer_->lockInfos_.size(), 1u);
}

// =============================================================================
// RecalcLockForBundle Tests
// =============================================================================

/**
 * @tc.name: RecalcLockForBundle_001
 * @tc.desc: Test RecalcLockForBundle with empty lockInfos_ and manager_ == nullptr
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_001, TestSize.Level1)
{
    // Branch: empty lockInfos_
    lockOptimizer_->lockInfos_.clear();
    lockOptimizer_->timerLockExpireTime_.store(0);
    lockOptimizer_->RecalcLockForBundle("com.test.app");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), 0);

    // Branch: manager_ == nullptr
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();

    optimizer.lockInfos_.clear();

    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = bootTime + defaultDuration;

    optimizer.lockInfos_.push_back(info);
    optimizer.timerLockExpireTime_.store(0);

    // manager_ == nullptr, AcquireRunningLockInternal returns early
    optimizer.RecalcLockForBundle("com.test.app");
    EXPECT_EQ(optimizer.timerLockExpireTime_.load(), 0);
}

/**
 * @tc.name: RecalcLockForBundle_002
 * @tc.desc: Test RecalcLockForBundle with empty bundleName parameter
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_002, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t presetExpireTime = bootTime + 1 * 1000000000LL; // 1s

    lockOptimizer_->lockInfos_.clear();
    lockOptimizer_->timerLockExpireTime_.store(presetExpireTime);
    lockOptimizer_->RecalcLockForBundle("");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), presetExpireTime);
}

/**
 * @tc.name: RecalcLockForBundle_003
 * @tc.desc: Test RecalcLockForBundle when nothing removed from lockInfos_
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_003, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t presetExpireTime = bootTime + 10 * 1000000000LL; // 10s

    lockOptimizer_->lockInfos_.clear();
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app1";
    info.lockExpireTime = bootTime + TimerManager::GetDefaultRunningLockDuration();

    lockOptimizer_->lockInfos_.push_back(info);
    lockOptimizer_->timerLockExpireTime_.store(presetExpireTime);

    // Remove non-matching bundleName, nothing removed
    lockOptimizer_->RecalcLockForBundle("com.test.app2");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), presetExpireTime);
}

/**
 * @tc.name: RecalcLockForBundle_004
 * @tc.desc: Test RecalcLockForBundle with 3 lockInfos, 1 removed by bundle match, 1 expired, 1 valid remains
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_004, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();
    int64_t expectedExpireTime = bootTime + APP_START_RUNNING_LOCK_DURATION_NS;

    lockOptimizer_->lockInfos_.clear();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = expectedExpireTime;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app2";
    info2.lockExpireTime = bootTime + defaultDuration;

    TimerLockOptimizer::TimerLockInfo info3;
    info3.timerId = 3;
    info3.wantBundleName = "com.test.app3";
    info3.lockExpireTime = bootTime - defaultDuration;

    lockOptimizer_->lockInfos_.push_back(info1);
    lockOptimizer_->lockInfos_.push_back(info2);
    lockOptimizer_->lockInfos_.push_back(info3);
    lockOptimizer_->timerLockExpireTime_.store(0);
    if (timerManager_ != nullptr) {
        timerManager_->lockExpiredTime_.store(0);
    }

    lockOptimizer_->RecalcLockForBundle("com.test.app2");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), expectedExpireTime);
}

/**
 * @tc.name: RecalcLockForBundle_005
 * @tc.desc: Test RecalcLockForBundle with 3 lockInfos, all expired and removed
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_005, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();
    int64_t presetExpireTime = bootTime + defaultDuration; // 1s

    lockOptimizer_->lockInfos_.clear();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "";
    info1.lockExpireTime = bootTime - defaultDuration;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app1";
    info2.lockExpireTime = bootTime + defaultDuration;

    TimerLockOptimizer::TimerLockInfo info3;
    info3.timerId = 3;
    info3.wantBundleName = "";
    info3.lockExpireTime = bootTime - defaultDuration;

    lockOptimizer_->lockInfos_.push_back(info1);
    lockOptimizer_->lockInfos_.push_back(info2);
    lockOptimizer_->lockInfos_.push_back(info3);
    lockOptimizer_->timerLockExpireTime_.store(presetExpireTime);
    if (timerManager_ != nullptr) {
        timerManager_->lockExpiredTime_.store(bootTime + 2 * 1000000000LL); // 2s, larger than any newExpireTime
    }

    lockOptimizer_->RecalcLockForBundle("com.test.app2");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), presetExpireTime);
}

/**
 * @tc.name: RecalcLockForBundle_006
 * @tc.desc: Test RecalcLockForBundle after sleep 0.1s, remove 10s lock, keep 1s lock
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_006, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();
    int64_t smallLockExpireTime = bootTime + defaultDuration; // 1s

    lockOptimizer_->lockInfos_.clear();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = bootTime + APP_START_RUNNING_LOCK_DURATION_NS; // 10s

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app2";
    info2.lockExpireTime = smallLockExpireTime; // 1s

    lockOptimizer_->lockInfos_.push_back(info1);
    lockOptimizer_->lockInfos_.push_back(info2);
    lockOptimizer_->timerLockExpireTime_.store(0);
    if (timerManager_ != nullptr) {
        timerManager_->lockExpiredTime_.store(0);
    }

    usleep(100000); // Sleep 0.1s

    // Remove 10s lock by bundle match (start ability type), 1s lock remains
    // Since removed entry has non-empty bundleName, extra 1s lock duration is added
    lockOptimizer_->RecalcLockForBundle("com.test.app1");
    int64_t currentBootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    EXPECT_GT(lockOptimizer_->timerLockExpireTime_.load(), smallLockExpireTime);
    EXPECT_LE(lockOptimizer_->timerLockExpireTime_.load(), currentBootTime + defaultDuration);
}

/**
 * @tc.name: RecalcLockForBundle_007
 * @tc.desc: Test RecalcLockForBundle after sleep 2s, remove 10s lock, add new 1s lock
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_007, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();

    lockOptimizer_->lockInfos_.clear();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = bootTime + APP_START_RUNNING_LOCK_DURATION_NS; // 10s

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app2";
    info2.lockExpireTime = bootTime + defaultDuration; // 1s

    lockOptimizer_->lockInfos_.push_back(info1);
    lockOptimizer_->lockInfos_.push_back(info2);
    lockOptimizer_->timerLockExpireTime_.store(0);
    if (timerManager_ != nullptr) {
        timerManager_->lockExpiredTime_.store(0);
    }

    sleep(2); // Sleep 2s, 1s lock expired

    // Remove 10s lock by bundle match (start ability type), 1s lock also expired -> lockInfos_ empty
    // Since removed entry has non-empty bundleName, extra 1s lock duration is added
    lockOptimizer_->RecalcLockForBundle("com.test.app1");
    EXPECT_EQ(lockOptimizer_->lockInfos_.size(), 0u);

    // timerLockExpireTime_ = currentBootTime (inside function) + defaultDuration
    // Should be >= currentBootTime (test) and <= currentBootTime + defaultDuration
    int64_t currentBootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    EXPECT_GE(lockOptimizer_->timerLockExpireTime_.load(), currentBootTime); // >= 0s
    EXPECT_LE(lockOptimizer_->timerLockExpireTime_.load(), currentBootTime + defaultDuration); // <= 1s
}

/**
 * @tc.name: RecalcLockForBundle_008
 * @tc.desc: Test RecalcLockForBundle when lockTime < 0
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, RecalcLockForBundle_008, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t presetExpireTime = bootTime - TimerManager::GetDefaultRunningLockDuration(); // 1s

    lockOptimizer_->lockInfos_.clear();
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "";
    info.lockExpireTime = presetExpireTime;

    lockOptimizer_->lockInfos_.push_back(info);
    lockOptimizer_->timerLockExpireTime_.store(presetExpireTime);
    timerManager_->lockExpiredTime_.store(0);

    // Remove non-matching bundleName, nothing removed
    lockOptimizer_->RecalcLockForBundle("com.test.app2");
    EXPECT_EQ(lockOptimizer_->timerLockExpireTime_.load(), presetExpireTime);
}

// =============================================================================
// QueryAllRunningApps Tests
// =============================================================================

/**
 * @tc.name: QueryAllRunningApps_001
 * @tc.desc: Test QueryAllRunningApps clears existing runningApps_
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, QueryAllRunningApps_001, TestSize.Level1)
{
    lockOptimizer_->runningApps_.insert("com.test.app1");
    lockOptimizer_->runningApps_.insert("com.test.app2");

    EXPECT_TRUE(lockOptimizer_->IsAppRunning("com.test.app1"));
    EXPECT_TRUE(lockOptimizer_->IsAppRunning("com.test.app2"));

    lockOptimizer_->QueryAllRunningApps();

    EXPECT_FALSE(lockOptimizer_->IsAppRunning("com.test.app1"));
    EXPECT_FALSE(lockOptimizer_->IsAppRunning("com.test.app2"));
}

// =============================================================================
// BatchAcquireRunningLock Tests
// =============================================================================

/**
 * @tc.name: BatchAcquireRunningLock_001
 * @tc.desc: Test BatchAcquireRunningLock with empty trigger list
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_001, TestSize.Level1)
{
    lockOptimizer_->lockInfos_.clear();
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    lockOptimizer_->BatchAcquireRunningLock(triggerList);
    EXPECT_TRUE(lockOptimizer_->lockInfos_.empty());
}

/**
 * @tc.name: BatchAcquireRunningLock_002
 * @tc.desc: Test BatchAcquireRunningLock with wakeup timer without wantAgent
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_002, TestSize.Level1)
{
    lockOptimizer_->lockInfos_.clear();

    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    // type=2 (ELAPSED_REALTIME_WAKEUP) means wakeup=true
    auto timer = TimerInfo::CreateTimerInfo(
        "test", 1, 2, 1000000, 0, 0, 0, false,
        nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer);

    lockOptimizer_->BatchAcquireRunningLock(triggerList);
    EXPECT_EQ(lockOptimizer_->lockInfos_.size(), 1u);
    EXPECT_EQ(lockOptimizer_->lockInfos_[0].timerId, 1u);
}

/**
 * @tc.name: BatchAcquireRunningLock_003
 * @tc.desc: Test BatchAcquireRunningLock with expired lockInfos_ entry
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_003, TestSize.Level1)
{
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();

    lockOptimizer_->lockInfos_.clear();
    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = bootTime - TimerManager::GetDefaultRunningLockDuration();

    lockOptimizer_->lockInfos_.push_back(info);

    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    lockOptimizer_->BatchAcquireRunningLock(triggerList);
    EXPECT_TRUE(lockOptimizer_->lockInfos_.empty());
}

/**
 * @tc.name: BatchAcquireRunningLock_004
 * @tc.desc: Test BatchAcquireRunningLock with START_ABILITY operation
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, BatchAcquireRunningLock_004, TestSize.Level1)
{
    lockOptimizer_->lockInfos_.clear();

    using OperationType = OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType;

    auto want = std::make_shared<AAFwk::Want>();
    want->SetElementName("com.test.app", "Ability");
    auto localPendingWant = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator", want, static_cast<int32_t>(OperationType::START_ABILITY));
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant);

    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    auto timer = TimerInfo::CreateTimerInfo(
        "test", 1, 2, 1000000, 0, 0, 0, false,
        nullptr, wantAgent, 0, 0, "");
    triggerList.push_back(timer);

    lockOptimizer_->BatchAcquireRunningLock(triggerList);
    EXPECT_EQ(lockOptimizer_->lockInfos_.size(), 1u);
    EXPECT_EQ(lockOptimizer_->lockInfos_[0].wantBundleName, "com.test.app");
}

// =============================================================================
// MergeNewTimers Tests
// =============================================================================

/**
 * @tc.name: MergeNewTimers_001
 * @tc.desc: Test MergeNewTimers with empty trigger list
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    optimizer.MergeNewTimers(triggerList, bootTime);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
    EXPECT_TRUE(optimizer.targetBundleNameCache_.empty());
}

/**
 * @tc.name: MergeNewTimers_002
 * @tc.desc: Test MergeNewTimers covering all branches
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, MergeNewTimers_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    int64_t bootTime = 1000000000LL;

    using OperationType = OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType;

    // non-wakeup timer (skipped)
    auto timer1 = TimerInfo::CreateTimerInfo("test1", 1, 3, 1000000, 0, 0, 0, false, nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer1);

    // wakeup without wantAgent (defaultDuration)
    auto timer2 = TimerInfo::CreateTimerInfo("test2", 2, 2, 1000000, 0, 0, 0, false, nullptr, nullptr, 0, 0, "");
    triggerList.push_back(timer2);

    // empty bundleName + START_ABILITY (defaultDuration)
    auto want3 = std::make_shared<AAFwk::Want>();
    auto localPendingWant3 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator3", want3, static_cast<int32_t>(OperationType::START_ABILITY));
    auto wantAgent3 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant3);
    auto timer3 = TimerInfo::CreateTimerInfo("test3", 3, 2, 1000000, 0, 0, 0, false, nullptr, wantAgent3, 0, 0, "");
    triggerList.push_back(timer3);

    // bundleName + SEND_COMMON_EVENT (empty bundleName returned, defaultDuration)
    auto want4 = std::make_shared<AAFwk::Want>();
    want4->SetElementName("com.test.app4", "Ability");
    auto localPendingWant4 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator4", want4, static_cast<int32_t>(OperationType::SEND_COMMON_EVENT));
    auto wantAgent4 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant4);
    auto timer4 = TimerInfo::CreateTimerInfo("test4", 4, 2, 1000000, 0, 0, 0, false, nullptr, wantAgent4, 0, 0, "");
    triggerList.push_back(timer4);

    // bundleName + START_ABILITY (10s)
    auto want5 = std::make_shared<AAFwk::Want>();
    want5->SetElementName("com.test.app5", "Ability");
    auto localPendingWant5 = std::make_shared<OHOS::AbilityRuntime::WantAgent::LocalPendingWant>(
        "creator5", want5, static_cast<int32_t>(OperationType::START_ABILITY));
    auto wantAgent5 = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(localPendingWant5);
    auto timer5 = TimerInfo::CreateTimerInfo("test5", 5, 2, 1000000, 0, 0, 0, false, nullptr, wantAgent5, 0, 0, "");
    triggerList.push_back(timer5);

    optimizer.MergeNewTimers(triggerList, bootTime);

    EXPECT_EQ(optimizer.lockInfos_.size(), 4u);
    EXPECT_TRUE(optimizer.lockInfos_[0].wantBundleName.empty());
    EXPECT_EQ(optimizer.lockInfos_[1].wantBundleName.empty(), true);
    EXPECT_TRUE(optimizer.lockInfos_[2].wantBundleName.empty()); // SEND_COMMON_EVENT returns empty bundleName
    EXPECT_LT(optimizer.lockInfos_[2].lockExpireTime, bootTime + APP_START_RUNNING_LOCK_DURATION_NS);
    EXPECT_EQ(optimizer.lockInfos_[3].wantBundleName, "com.test.app5");
    EXPECT_EQ(optimizer.lockInfos_[3].lockExpireTime, bootTime + APP_START_RUNNING_LOCK_DURATION_NS);
    // Only timer5 with START_ABILITY + non-empty bundleName should be cached
    EXPECT_EQ(optimizer.targetBundleNameCache_.size(), 1u);
    EXPECT_EQ(optimizer.targetBundleNameCache_[5], "com.test.app5");
}

// =============================================================================
// SortAndDeduplicate Tests
// =============================================================================

/**
 * @tc.name: SortAndDeduplicate_001
 * @tc.desc: Test SortAndDeduplicate with empty list
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_001, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    optimizer.SortAndDeduplicate(bootTime);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: SortAndDeduplicate_002
 * @tc.desc: Test SortAndDeduplicate removes expired entries
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_002, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();

    TimerLockOptimizer::TimerLockInfo info;
    info.timerId = 1;
    info.wantBundleName = "com.test.app";
    info.lockExpireTime = bootTime - TimerManager::GetDefaultRunningLockDuration();

    optimizer.lockInfos_.push_back(info);
    optimizer.SortAndDeduplicate(bootTime);
    EXPECT_TRUE(optimizer.lockInfos_.empty());
}

/**
 * @tc.name: SortAndDeduplicate_003
 * @tc.desc: Test SortAndDeduplicate removes duplicates keeping largest expireTime
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_003, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app";
    info1.lockExpireTime = bootTime + defaultDuration;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app";
    info2.lockExpireTime = bootTime + APP_START_RUNNING_LOCK_DURATION_NS;

    optimizer.lockInfos_.push_back(info1);
    optimizer.lockInfos_.push_back(info2);
    optimizer.SortAndDeduplicate(bootTime);

    EXPECT_EQ(optimizer.lockInfos_.size(), 1u);
    EXPECT_EQ(optimizer.lockInfos_[0].lockExpireTime, bootTime + APP_START_RUNNING_LOCK_DURATION_NS);
}

/**
 * @tc.name: SortAndDeduplicate_004
 * @tc.desc: Test SortAndDeduplicate sorts by expireTime descending
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, SortAndDeduplicate_004, TestSize.Level1)
{
    TimerLockOptimizer optimizer(nullptr);
    int64_t bootTime = TimeUtils::GetBootTimeNs().time_since_epoch().count();
    int64_t defaultDuration = TimerManager::GetDefaultRunningLockDuration();

    TimerLockOptimizer::TimerLockInfo info1;
    info1.timerId = 1;
    info1.wantBundleName = "com.test.app1";
    info1.lockExpireTime = bootTime + defaultDuration;

    TimerLockOptimizer::TimerLockInfo info2;
    info2.timerId = 2;
    info2.wantBundleName = "com.test.app2";
    info2.lockExpireTime = bootTime + APP_START_RUNNING_LOCK_DURATION_NS;

    optimizer.lockInfos_.push_back(info1);
    optimizer.lockInfos_.push_back(info2);
    optimizer.SortAndDeduplicate(bootTime);

    EXPECT_EQ(optimizer.lockInfos_.size(), 2u);
    EXPECT_EQ(optimizer.lockInfos_[0].lockExpireTime, bootTime + APP_START_RUNNING_LOCK_DURATION_NS);
}

// =============================================================================
// IsAbilityStartingOperation Tests
// =============================================================================

/**
 * @tc.name: IsAbilityStartingOperation_001
 * @tc.desc: Test IsAbilityStartingOperation with all operation types
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(TimerLockOptimizerTest, IsAbilityStartingOperation_001, TestSize.Level1)
{
    using OperationType = OHOS::AbilityRuntime::WantAgent::WantAgentConstant::OperationType;

    EXPECT_FALSE(lockOptimizer_->IsAbilityStartingOperation(OperationType::SEND_COMMON_EVENT));
    EXPECT_FALSE(lockOptimizer_->IsAbilityStartingOperation(OperationType::UNKNOWN_TYPE));
    EXPECT_TRUE(lockOptimizer_->IsAbilityStartingOperation(OperationType::START_ABILITY));
}

#endif // RUNNING_LOCK_OPTIMIZE

} // namespace
} // namespace MiscServices
} // namespace OHOS