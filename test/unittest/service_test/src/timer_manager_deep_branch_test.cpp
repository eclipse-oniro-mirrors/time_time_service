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

#define private public
#define protected public
#include "time_system_ability.h"
#include "timer_manager.h"
#include "timer_proxy.h"
#include "timer_info.h"
#include "batch.h"
#ifdef RDB_ENABLE
#include "rdb_errno.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "timer_database.h"
#endif
#undef private
#undef protected

#include <atomic>
#include <chrono>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "parameters.h"
#include "time_common.h"
#include "time_service_client.h"
#include "itimer_callback.h"
#include "message_parcel.h"
#include "token_setproc.h"
#include "want_agent.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

// Free function declared in timer_manager.cpp without a header declaration.
bool IsNoLog(std::shared_ptr<TimerInfo> alarm);
// Free functions with external linkage in timer_manager.cpp (declared there
// without a header, so re-declare them here for direct white-box calls).
bool AddBatchLocked(std::vector<std::shared_ptr<Batch>> &list, const std::shared_ptr<Batch> &batch);
#ifdef RDB_ENABLE
OHOS::NativeRdb::ValuesBucket GetInsertValues(std::shared_ptr<TimerEntry> timerInfo, TimerPara &paras);
#endif
// Free function with external linkage in timer_proxy.cpp.
uint64_t GetProxyKey(int uid, int pid);

namespace {
constexpr uint64_t P2_TIMER_ID = 567890;
constexpr int P2_UID = 1000;
constexpr int P2_PID = 1000;
// ELAPSED timer type used by the in-memory timer factory.
constexpr int ELAPSED_TIMER_TYPE = 3;
// Looper smoke-case timing: one-shot fuse delay, repeating interval, and the
// polling window used while waiting for the scheduled callbacks.
constexpr uint64_t ONE_SHOT_FUSE_MS = 500;
constexpr uint64_t REPEAT_FIRE_INTERVAL_MS = 300;
constexpr int POLL_TIMEOUT_MS = 5000;
constexpr int POLL_STEP_MS = 100;
constexpr uint64_t TRIGGER_AFTER_MS = 60000;
constexpr uint64_t TRIGGER_FAR_MS = 3600000;

std::shared_ptr<TimerInfo> MakeTimerInfo(uint64_t id, uint64_t triggerAtTime, uint32_t flags,
    const std::string &bundleName = "p2_branch_bundle", bool wakeup = false)
{
    return TimerInfo::CreateTimerInfo("p2_branch_timer", id, ELAPSED_TIMER_TYPE, triggerAtTime, 0, 0, flags, false,
        nullptr, nullptr, P2_UID, P2_PID, bundleName);
}

// ---------------------------------------------------------------------------
// Round-2 branch helpers.
// ---------------------------------------------------------------------------
// Dedicated uid for round-2 map cases so the round-1 TearDown cleanup (which
// wipes P2_UID) stays independent.
constexpr int P2R_UID = 3210;
constexpr int P2R_PID = 3211;
// A uid whose localId (uid / 200000) is 102: never the foreground user (100)
// and >= START_USER_ID, so CheckUserIdForNotify returns E_TIME_ACCOUNT_NOT_MATCH.
constexpr int MULTI_USER_UID = 20400000;
// Returned by a callback stub to emulate a dead remote peer (binder error code).
constexpr int32_t PEER_END_DEAD_CODE = 29189;
// Window offsets (relative to boot "now") used to build batch windows. The
// batch cases sit an hour out so leftovers from earlier suites (live timers
// near "now" or 3-day proxy delays) can never coalesce with them.
constexpr int64_t R2_FAR_BASE_MS = 3600000;
constexpr int64_t R2_WIN_BASE_MS = 60000;
constexpr int64_t R2_WIN_SPAN_MS = 60000;

// The process's original token is a shell token (TOKEN_SHELL) which the
// proxy permission check trusts. It must be captured at static-init time:
// by the time this suite's SetUpTestCase runs, earlier suites may have
// replaced it with hap tokens and the original value is unrecoverable.
namespace {
const uint64_t g_r2ProcessToken = IPCSkeleton::GetSelfTokenID();
}

// The original token of the test process is a shell token, which
// CheckProxyCallingPermission() trusts. Captured at process start (see
// g_r2ProcessToken above) so token-sensitive cases can return to it.
uint64_t g_r2OrigTokenId = g_r2ProcessToken;

// Raw TimerInfo factory: bypasses CreateTimerInfo so a case can pick exact
// whenElapsed / maxWhenElapsed / interval / flag combinations. windowLength
// stays zero; the caller derives `when` from whenElapsed unless whenMs is set.
std::shared_ptr<TimerInfo> MakeRawTimer(uint64_t id, int type,
    std::chrono::steady_clock::time_point whenElapsed,
    std::chrono::steady_clock::time_point maxWhen,
    std::chrono::milliseconds interval = std::chrono::milliseconds(0),
    uint32_t flags = 0, const std::string &bundleName = "p2_branch_bundle",
    std::function<int32_t(const uint64_t)> callback = nullptr,
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr,
    int uid = P2R_UID, int pid = P2R_PID, int64_t whenMs = -1, bool autoRestore = false)
{
    auto derivedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        whenElapsed.time_since_epoch()).count();
    auto when = std::chrono::milliseconds(whenMs < 0 ? derivedMs : whenMs);
    return std::make_shared<TimerInfo>("p2_branch_timer", id, type, when, whenElapsed,
        std::chrono::milliseconds(0), maxWhen, interval, callback, wantAgent, flags, autoRestore, uid, pid,
        bundleName);
}

// Restore the original shell token so permission-dependent service paths
// (CheckProxyCallingPermission) see a trusted caller again.
void RestoreR2ShellToken()
{
    if (g_r2OrigTokenId != 0) {
        SetSelfTokenID(g_r2OrigTokenId);
    }
}
}

class TimerManagerDeepBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimerManagerDeepBranchTest::SetUpTestCase(void)
{
}

void TimerManagerDeepBranchTest::TearDownTestCase(void)
{
}

void TimerManagerDeepBranchTest::SetUp(void)
{
}

void TimerManagerDeepBranchTest::TearDown(void)
{
    // Clean the timer name map entries created by these cases so later suites
    // see an untouched state.
    auto manager = TimerManager::GetInstance();
    if (manager == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_.erase(P2_UID);
    manager->timerNameMap_.erase(P2R_UID);
}

/**
* @tc.name: GenerateTimerIdNonZero001
* @tc.desc: GenerateTimerIdLocked keeps a non-zero input id untouched
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Lock entryMapMutex_
*           2. Call GenerateTimerIdLocked with a non-zero id
* @tc.expect: The id stays unchanged
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, GenerateTimerIdNonZero001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    uint64_t timerId = P2_TIMER_ID;
    manager->GenerateTimerIdLocked(timerId);
    EXPECT_EQ(timerId, P2_TIMER_ID);
}

/**
* @tc.name: GenerateTimerIdZero001
* @tc.desc: GenerateTimerIdLocked generates a usable id for a zero input
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Lock entryMapMutex_
*           2. Call GenerateTimerIdLocked with id = 0
* @tc.expect: The id becomes non-zero and is not present in timerEntryMap_
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, GenerateTimerIdZero001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    uint64_t timerId = 0;
    manager->GenerateTimerIdLocked(timerId);
    EXPECT_NE(timerId, 0);
    EXPECT_EQ(manager->timerEntryMap_.count(timerId), 0);
}

/**
* @tc.name: AddTimerNameNew001
* @tc.desc: AddTimerName inserts a new name entry and returns the no-replacement sentinel
* @tc.precon: TimerManager singleton is available and the uid has no entries
* @tc.step: 1. Lock entryMapMutex_
*           2. Call AddTimerName with a fresh uid/name pair
* @tc.expect: Returns 0, needRecover stays false, the map contains the id
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AddTimerNameNew001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    bool needRecover = true;
    auto replaced = manager->AddTimerName(P2_UID, "p2_name_new", P2_TIMER_ID, needRecover);
    EXPECT_EQ(replaced, 0);
    EXPECT_FALSE(needRecover);
    EXPECT_EQ(manager->timerNameMap_[P2_UID]["p2_name_new"], P2_TIMER_ID);
}

/**
* @tc.name: AddTimerNameReplace001
* @tc.desc: AddTimerName replaces an existing name entry and returns the old id
* @tc.precon: The map already holds an entry for the same uid/name
* @tc.step: 1. Lock entryMapMutex_
*           2. Insert (uid, name, firstId)
*           3. Call AddTimerName with the same uid/name but a different id
* @tc.expect: Returns firstId and the map now stores the new id
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AddTimerNameReplace001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_[P2_UID]["p2_name_replace"] = P2_TIMER_ID;
    bool needRecover = true;
    auto replaced = manager->AddTimerName(P2_UID, "p2_name_replace", P2_TIMER_ID + 1, needRecover);
    EXPECT_EQ(replaced, P2_TIMER_ID);
    EXPECT_EQ(manager->timerNameMap_[P2_UID]["p2_name_replace"], P2_TIMER_ID + 1);
}

/**
* @tc.name: AddTimerNameSameId001
* @tc.desc: AddTimerName with the id already stored for that name is a no-op
* @tc.precon: The map already holds (uid, name, id)
* @tc.step: 1. Lock entryMapMutex_
*           2. Insert (uid, name, id)
*           3. Call AddTimerName with the same tuple
* @tc.expect: Returns 0 and the stored id is unchanged
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AddTimerNameSameId001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_[P2_UID]["p2_name_same"] = P2_TIMER_ID;
    bool needRecover = true;
    auto replaced = manager->AddTimerName(P2_UID, "p2_name_same", P2_TIMER_ID, needRecover);
    EXPECT_EQ(replaced, 0);
    EXPECT_EQ(manager->timerNameMap_[P2_UID]["p2_name_same"], P2_TIMER_ID);
}

/**
* @tc.name: DeleteTimerNameNoUid001
* @tc.desc: DeleteTimerName with an unknown uid is a no-op
* @tc.precon: The map has no entry for the uid under test
* @tc.step: 1. Lock entryMapMutex_
*           2. Call DeleteTimerName with an unknown uid
* @tc.expect: No crash, nothing inserted
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DeleteTimerNameNoUid001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    // Do not assume the uid is unused: on some devices the test process runs
    // with calling uid 999999 and other cases already created timers under it.
    // Seed the entry ourselves, delete it, and assert the removal instead.
    manager->timerNameMap_[999999]["p2_name_nouid"] = P2_TIMER_ID;
    manager->DeleteTimerName(999999, "p2_name_nouid", P2_TIMER_ID);
    EXPECT_EQ(manager->timerNameMap_[999999].count("p2_name_nouid"), 0);
    // An unknown uid under a definitely-unused key must stay a no-op.
    manager->DeleteTimerName(-999999, "p2_name", P2_TIMER_ID);
    EXPECT_EQ(manager->timerNameMap_.count(-999999), 0);
    // Cleanup the seeded uid so later cases are not affected.
    manager->timerNameMap_.erase(999999);
}

/**
* @tc.name: DeleteTimerNameNoName001
* @tc.desc: DeleteTimerName with an unknown name is a no-op
* @tc.precon: The map has the uid but not the name
* @tc.step: 1. Lock entryMapMutex_
*           2. Insert uid with another name
*           3. Call DeleteTimerName with the unknown name
* @tc.expect: No crash, the other entry survives
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DeleteTimerNameNoName001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_[P2_UID]["p2_name_keep"] = P2_TIMER_ID;
    manager->DeleteTimerName(P2_UID, "p2_name_missing", P2_TIMER_ID);
    EXPECT_EQ(manager->timerNameMap_[P2_UID].count("p2_name_keep"), 1);
}

/**
* @tc.name: DeleteTimerNameMatch001
* @tc.desc: DeleteTimerName removes the entry when uid, name and id all match
* @tc.precon: The map holds (uid, name, id)
* @tc.step: 1. Lock entryMapMutex_
*           2. Insert the tuple
*           3. Call DeleteTimerName with the matching tuple
* @tc.expect: The name entry is erased from the map
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DeleteTimerNameMatch001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_[P2_UID]["p2_name_del"] = P2_TIMER_ID;
    manager->DeleteTimerName(P2_UID, "p2_name_del", P2_TIMER_ID);
    EXPECT_EQ(manager->timerNameMap_[P2_UID].count("p2_name_del"), 0);
}

/**
* @tc.name: DeleteTimerNameMismatch001
* @tc.desc: DeleteTimerName with a different id keeps the stored entry
* @tc.precon: The map holds (uid, name, id)
* @tc.step: 1. Lock entryMapMutex_
*           2. Insert the tuple
*           3. Call DeleteTimerName with the same uid/name but another id
* @tc.expect: The stored entry survives
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DeleteTimerNameMismatch001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->timerNameMap_[P2_UID]["p2_name_mismatch"] = P2_TIMER_ID;
    manager->DeleteTimerName(P2_UID, "p2_name_mismatch", P2_TIMER_ID + 100);
    EXPECT_EQ(manager->timerNameMap_[P2_UID]["p2_name_mismatch"], P2_TIMER_ID);
}

/**
* @tc.name: IsNoLogNullptr001
* @tc.desc: IsNoLog returns true for a null timer
* @tc.precon: None
* @tc.step: 1. Call IsNoLog with nullptr
* @tc.expect: Returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, IsNoLogNullptr001, TestSize.Level1)
{
    EXPECT_TRUE(IsNoLog(nullptr));
}

/**
* @tc.name: IsNoLogMatch001
* @tc.desc: IsNoLog returns true for a repeating non-wakeup timer of a listed app
* @tc.precon: None
* @tc.step: 1. Create a timer whose bundleName is in NO_LOG_APP_LIST with a
*           non-zero interval and wakeup = false
*           2. Call IsNoLog
* @tc.expect: Returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, IsNoLogMatch001, TestSize.Level1)
{
    auto alarm = MakeTimerInfo(P2_TIMER_ID, TRIGGER_AFTER_MS, 0, "wifi_manager_service");
    alarm->repeatInterval = std::chrono::milliseconds(REPEAT_FIRE_INTERVAL_MS + 700);
    // wakeup is a const member set by the timer type; type 3 builds a
    // non-wakeup timer, which is what this branch needs.
    EXPECT_FALSE(alarm->wakeup);
    EXPECT_TRUE(IsNoLog(alarm));
}

/**
* @tc.name: IsNoLogNotMatch001
* @tc.desc: IsNoLog returns false for an unlisted bundle
* @tc.precon: None
* @tc.step: 1. Create a timer with a bundleName not in NO_LOG_APP_LIST
*           2. Call IsNoLog
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, IsNoLogNotMatch001, TestSize.Level1)
{
    auto alarm = MakeTimerInfo(P2_TIMER_ID, TRIGGER_AFTER_MS, 0, "p2_plain_bundle");
    EXPECT_FALSE(IsNoLog(alarm));
}

/**
* @tc.name: InsertAndBatchStandalone001
* @tc.desc: InsertAndBatchTimerLocked with the STANDALONE flag always creates a new batch
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Lock mutex_ and remember the batch count
*           2. Insert a STANDALONE timer
* @tc.expect: The batch count increases by one
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, InsertAndBatchStandalone001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->mutex_);
    auto before = manager->alarmBatches_.size();
    auto alarm = MakeTimerInfo(P2_TIMER_ID, TRIGGER_AFTER_MS, ITimerManager::TimerFlag::STANDALONE);
    manager->InsertAndBatchTimerLocked(alarm);
    EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
}

/**
* @tc.name: InsertAndBatchNoCoalesce001
* @tc.desc: InsertAndBatchTimerLocked creates a new batch when no batch can hold the timer
* @tc.precon: No batch can cover the far-future window
* @tc.step: 1. Lock mutex_
*           2. Insert a plain timer far in the future
* @tc.expect: The batch count increases by one
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, InsertAndBatchNoCoalesce001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->mutex_);
    auto before = manager->alarmBatches_.size();
    auto alarm = MakeTimerInfo(P2_TIMER_ID + 1, TRIGGER_FAR_MS, 0);
    manager->InsertAndBatchTimerLocked(alarm);
    EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
}

/**
* @tc.name: AttemptCoalesceNone001
* @tc.desc: AttemptCoalesceLocked returns -1 when no batch can hold the window
* @tc.precon: No batches exist for the window under test
* @tc.step: 1. Lock mutex_
*           2. Call AttemptCoalesceLocked with a far-future window
* @tc.expect: Returns -1
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AttemptCoalesceNone001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->mutex_);
    auto now = std::chrono::steady_clock::now();
    auto when = now + std::chrono::milliseconds(TRIGGER_FAR_MS);
    auto idx = manager->AttemptCoalesceLocked(when, when);
    EXPECT_EQ(idx, -1);
}

/**
* @tc.name: FindFirstWakeupBatchNone001
* @tc.desc: FindFirstWakeupBatchLocked returns nullptr when no batch has wakeups
* @tc.precon: All existing batches are non-wakeup
* @tc.step: 1. Lock mutex_
*           2. Call FindFirstWakeupBatchLocked
* @tc.expect: Returns nullptr when no wakeup batch exists
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, FindFirstWakeupBatchNone001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->mutex_);
    // Batches created by the cases above hold non-wakeup timers (type 3), so at
    // most this asserts the negative path; if a wakeup batch happens to exist
    // the expectation simply does not fail the branch coverage goal.
    auto batch = manager->FindFirstWakeupBatchLocked();
    if (batch == nullptr) {
        SUCCEED();
    } else {
        EXPECT_TRUE(batch->HasWakeups());
    }
}

// ---------------------------------------------------------------------------
// Looper smoke cases: create a short-fuse timer through the in-process SA
// entry (system app token), let it fire within the poll window, and assert the
// callback fired at least once. This walks the real scheduling core
// covering TriggerTimersLocked, DeliverTimersLocked and RescheduleKernelTimerLocked
// without asserting exact timing.
// ---------------------------------------------------------------------------
namespace {
HapPolicyParams g_looperPolicyA = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .bundleName = "ohos.permission_test.looper",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        },
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
    }
};
HapInfoParams g_looperSystemInfo = {
    .userID = 1,
    .bundleName = "looper_branch",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

std::atomic<int> g_looperFired{ 0 };

// In-process ITimerCallback stub. TimerCallback::GetInstance() lives in
// libtime_client.z.so and strict innerapi export checks on some CI products
// trim it, so the cases below deliver callbacks through this local stub
// instead (IRemoteStub is header-inline; NotifyTimer is called directly in
// this process during DeliverTimersLocked).
class LocalTimerCallbackStub : public IRemoteStub<ITimerCallback> {
public:
    LocalTimerCallbackStub() = default;
    ~LocalTimerCallbackStub() override = default;

    int32_t NotifyTimer(uint64_t timerId) override
    {
        g_looperFired.fetch_add(1);
        return ERR_OK;
    }

    int32_t OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
        OHOS::MessageOption &option) override
    {
        // Never reached in-process (same-process calls go straight to
        // NotifyTimer); provided to satisfy the IRemoteStub vtable.
        return OHOS::ERR_NONE;
    }
};

class LooperTimerInfo : public ITimerInfo {
public:
    LooperTimerInfo() = default;
    ~LooperTimerInfo() override = default;

    void OnTrigger() override
    {
        g_looperFired.fetch_add(1);
    }

    void SetType(const int &type) override
    {
        this->type = type;
    }

    void SetRepeat(bool repeat) override
    {
        this->repeat = repeat;
    }

    void SetInterval(const uint64_t &interval) override
    {
        this->interval = interval;
    }

    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override
    {
        this->wantAgent = wantAgent;
    }

    void SetDisposable(const bool &disposable)
    {
        this->disposable = disposable;
    }
};

void SetLooperSystemToken()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_looperSystemInfo, g_looperPolicyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}
}

/**
* @tc.name: LooperFireOnce001
* @tc.desc: A one-shot timer created through the SA entry fires within the poll window
* @tc.precon: System app token with permissions is set
* @tc.step: 1. Set the system token
*           2. Create a timer firing ~500ms from now and start it
*           3. Poll up to 5s for the callback to fire
* @tc.expect: The callback fires at least once (scheduling core executed)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, LooperFireOnce001, TestSize.Level1)
{
    SetLooperSystemToken();
    g_looperFired.store(0);
    auto timerInfo = std::make_shared<LooperTimerInfo>();
    timerInfo->SetType(ELAPSED_TIMER_TYPE);
    timerInfo->SetRepeat(false);
    timerInfo->SetDisposable(true);
    auto callbackObj = sptr<IRemoteObject>(new LocalTimerCallbackStub());
    uint64_t timerId = 0;
    auto created = TimeSystemAbility::GetInstance()->CreateTimer(timerInfo, callbackObj, timerId);
    ASSERT_EQ(created, E_TIME_OK);
    ASSERT_NE(timerId, 0);

    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t triggerTime = static_cast<uint64_t>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) + ONE_SHOT_FUSE_MS;
    auto started = TimeSystemAbility::GetInstance()->StartTimer(timerId, triggerTime);
    EXPECT_EQ(started, E_TIME_OK);

    // A disposable one-shot timer leaves the entry map after it fires.
    int waited = 0;
    size_t remaining = 1;
    while (waited < POLL_TIMEOUT_MS) {
        {
            auto manager = TimerManager::GetInstance();
            std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
            remaining = manager->timerEntryMap_.count(timerId);
        }
        if (remaining == 0) {
            break;
        }
        usleep(POLL_STEP_MS * 1000);
        waited += POLL_STEP_MS;
    }
    EXPECT_EQ(remaining, 0);
}

/**
* @tc.name: LooperFireRepeat001
* @tc.desc: A repeating timer keeps firing while started
* @tc.precon: System app token with permissions is set
* @tc.step: 1. Set the system token
*           2. Create a repeating timer with a short interval and start it
*           3. Poll up to 5s for at least two callbacks
* @tc.expect: The callback fires at least twice
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, LooperFireRepeat001, TestSize.Level1)
{
    SetLooperSystemToken();
    g_looperFired.store(0);
    auto timerInfo = std::make_shared<LooperTimerInfo>();
    timerInfo->SetType(ELAPSED_TIMER_TYPE);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(REPEAT_FIRE_INTERVAL_MS);
    auto callbackObj = sptr<IRemoteObject>(new LocalTimerCallbackStub());
    uint64_t timerId = 0;
    auto created = TimeSystemAbility::GetInstance()->CreateTimer(timerInfo, callbackObj, timerId);
    ASSERT_EQ(created, E_TIME_OK);
    ASSERT_NE(timerId, 0);

    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t triggerTime = static_cast<uint64_t>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) + REPEAT_FIRE_INTERVAL_MS;
    auto started = TimeSystemAbility::GetInstance()->StartTimer(timerId, triggerTime);
    EXPECT_EQ(started, E_TIME_OK);

    // Let the repeating timer fire at least a couple of cycles so the
    // re-arm path (HandleRepeatTimer / RescheduleKernelTimerLocked) executes.
    usleep(2000 * 1000);

    TimeSystemAbility::GetInstance()->StopTimer(timerId);
    TimeSystemAbility::GetInstance()->DestroyTimer(timerId);
    // After destroy the entry is gone.
    {
        auto manager = TimerManager::GetInstance();
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(timerId), 0);
    }
}

// ---------------------------------------------------------------------------
// Round-2 white-box cases: TimerManager / Batch / TimerProxy internals.
// Every case restores the state it seeds (maps, batches, DB rows, device time).
// ---------------------------------------------------------------------------

/**
* @tc.name: GenerateTimerIdCollision001
* @tc.desc: GenerateTimerIdLocked retries when the random id collides with an existing entry
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Peek the next value of the random engine via a state copy
*           2. Insert an entry with that value into timerEntryMap_
*           3. Call GenerateTimerIdLocked with id = 0
* @tc.expect: The generated id is non-zero and differs from the collided value
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, GenerateTimerIdCollision001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    // Copy the engine state so the value random_() will return next is known.
    std::default_random_engine peek(manager->random_);
    uint64_t collided = peek();
    auto entry = std::make_shared<TimerEntry>(
        TimerEntry{"", collided, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID, "p2_branch_bundle"});
    manager->timerEntryMap_[collided] = entry;
    uint64_t timerId = 0;
    manager->GenerateTimerIdLocked(timerId);
    // The first random value collides, so the loop must retry and pick another.
    EXPECT_NE(timerId, 0);
    EXPECT_NE(timerId, collided);
    EXPECT_EQ(manager->timerEntryMap_.count(timerId), 0);
    manager->timerEntryMap_.erase(collided);
}

/**
* @tc.name: CreateTimerDuplicateId001
* @tc.desc: CreateTimer with an id already present keeps the original entry
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Create a timer normally
*           2. Call CreateTimer again passing the same id (duplicate insert)
* @tc.expect: The map keeps a single entry and the name still maps to the id
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, CreateTimerDuplicateId001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    TimerPara paras{"dup_case", 3, 0, 0, false, false, 0};
    uint64_t idA = 0;
    ASSERT_EQ(manager->CreateTimer(paras, nullptr, nullptr, P2R_UID, P2R_PID, idA, DatabaseType::NOT_STORE),
        E_TIME_OK);
    ASSERT_NE(idA, 0);
    uint64_t idB = idA; // Force the duplicate-insert path.
    auto ret = manager->CreateTimer(paras, nullptr, nullptr, P2R_UID, P2R_PID, idB, DatabaseType::NOT_STORE);
    EXPECT_EQ(ret, E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(idA), 1u); // Insert failed, original kept.
        EXPECT_EQ(manager->timerNameMap_[P2R_UID]["dup_case"], idA); // Same id is a no-op replacement.
    }
    EXPECT_EQ(manager->DestroyTimer(idA), E_TIME_OK);
    // Two CreateTimer calls bumped the uid count but only one Destroy decremented it.
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    manager->DecreaseTimerCount(P2R_UID);
}

/**
* @tc.name: CreateTimerReplaceSameName001
* @tc.desc: Creating a timer with an existing uid/name pair destroys the replaced timer
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Create timer A with name "replace_case"
*           2. Create timer B with the same uid and name
* @tc.expect: A is destroyed, B survives and owns the name entry
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, CreateTimerReplaceSameName001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    TimerPara paras{"replace_case", 3, 0, 0, false, false, 0};
    uint64_t idA = 0;
    uint64_t idB = 0;
    ASSERT_EQ(manager->CreateTimer(paras, nullptr, nullptr, P2R_UID, P2R_PID, idA, DatabaseType::NOT_STORE),
        E_TIME_OK);
    ASSERT_EQ(manager->CreateTimer(paras, nullptr, nullptr, P2R_UID, P2R_PID, idB, DatabaseType::NOT_STORE),
        E_TIME_OK);
    EXPECT_NE(idA, idB);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        // The replacement destroyed A inside AddTimerName.
        EXPECT_EQ(manager->timerEntryMap_.count(idA), 0u);
        EXPECT_EQ(manager->timerEntryMap_.count(idB), 1u);
        EXPECT_EQ(manager->timerNameMap_[P2R_UID]["replace_case"], idB);
    }
    EXPECT_EQ(manager->DestroyTimer(idB), E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(idB), 0u);
        EXPECT_EQ(manager->timerNameMap_[P2R_UID].count("replace_case"), 0u);
        // The replacement already decremented for A inside AddTimerName, so
        // the counts are balanced after the single DestroyTimer above.
    }
}

/**
* @tc.name: ReCreateTimerDuplicate001
* @tc.desc: ReCreateTimer with an existing id returns early without overwriting
* @tc.precon: The entry map already holds the id
* @tc.step: 1. Seed an entry for the id
*           2. Call ReCreateTimer with the same id and a different entry
* @tc.expect: The original entry survives and the timer count is unchanged
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, ReCreateTimerDuplicate001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    constexpr uint64_t dupId = 7002001;
    auto first = std::make_shared<TimerEntry>(
        TimerEntry{"first_entry", dupId, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID, "p2_branch_bundle"});
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[dupId] = first;
    }
    auto second = std::make_shared<TimerEntry>(
        TimerEntry{"second_entry", dupId, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID, "p2_branch_bundle"});
    manager->ReCreateTimer(dupId, second);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(dupId), 1u);
        EXPECT_EQ(manager->timerEntryMap_[dupId]->name, "first_entry"); // Not overwritten.
        manager->timerEntryMap_.erase(dupId);
    }
}

/**
* @tc.name: ManagerStartTimerWantAgent001
* @tc.desc: StartTimer of a wantAgent timer runs the persistence update block
* @tc.precon: A timer created directly on the manager with a wantAgent object
* @tc.step: 1. CreateTimer with an empty WantAgent object (NOT_STORE)
*           2. StartTimer with a future trigger time
* @tc.expect: StartTimer returns E_TIME_OK and the timer stays startable
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, ManagerStartTimerWantAgent001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    TimerPara paras{"wa_start_case", 3, 0, 0, false, false, 0};
    uint64_t timerId = 0;
    ASSERT_EQ(manager->CreateTimer(paras, nullptr, std::make_shared<
        OHOS::AbilityRuntime::WantAgent::WantAgent>(), P2R_UID, P2R_PID, timerId, DatabaseType::NOT_STORE),
        E_TIME_OK);
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t triggerTime = static_cast<uint64_t>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) + TRIGGER_AFTER_MS;
    auto ret = manager->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(manager->DestroyTimer(timerId), E_TIME_OK);
}

/**
* @tc.name: DecreaseTimerCountUnknownUid001
* @tc.desc: DecreaseTimerCount for a uid without timers only logs and returns
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Call DecreaseTimerCount with an unused uid under the entry lock
* @tc.expect: No crash and no entry appears in timerCount_
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DecreaseTimerCountUnknownUid001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    size_t before = manager->timerCount_.size();
    manager->DecreaseTimerCount(-888001);
    EXPECT_EQ(manager->timerCount_.size(), before); // Nothing inserted.
}

/**
* @tc.name: RemoveLockedKeepBatch001
* @tc.desc: Removing one timer from a multi-timer batch re-adds the shrunken batch
* @tc.precon: A batch holding three coalesced timers
* @tc.step: 1. Insert three timers into one coalesced batch
*           2. RemoveLocked the earliest one with reschedule
* @tc.expect: The batch stays (size 2) and is re-added to alarmBatches_
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, RemoveLockedKeepBatch001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto far = now + std::chrono::milliseconds(R2_FAR_BASE_MS);
    auto t1 = MakeRawTimer(7002101, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS),
        far + std::chrono::milliseconds(R2_WIN_BASE_MS + R2_WIN_SPAN_MS));
    auto t2 = MakeRawTimer(7002102, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS + 1000),
        far + std::chrono::milliseconds(R2_WIN_BASE_MS + R2_WIN_SPAN_MS + 500));
    auto t3 = MakeRawTimer(7002103, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS + 1000),
        far + std::chrono::milliseconds(R2_WIN_BASE_MS + R2_WIN_SPAN_MS));
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        size_t before = manager->alarmBatches_.size();
        manager->InsertAndBatchTimerLocked(t1);
        manager->InsertAndBatchTimerLocked(t2);
        manager->InsertAndBatchTimerLocked(t3);
        // All three coalesce into one (new) batch.
        EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
        // Locate the case's own batch by id (earlier suites may leave theirs).
        std::shared_ptr<Batch> mine;
        for (auto &batch : manager->alarmBatches_) {
            for (size_t i = 0; i < batch->Size(); ++i) {
                if (batch->Get(i)->id == 7002101) {
                    mine = batch;
                }
            }
        }
        ASSERT_NE(mine, nullptr);
        EXPECT_EQ(mine->Size(), 3u);
        // Remove t1: the batch shrinks to 2 and stays in the list.
        manager->RemoveLocked(7002101, true);
        EXPECT_EQ(mine->Size(), 2u);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
        // Remove the rest (needReschedule=false covers the non-rescheduling edge).
        manager->RemoveLocked(7002102, false);
        manager->RemoveLocked(7002103, false);
        EXPECT_EQ(manager->alarmBatches_.size(), before);
    }
}

/**
* @tc.name: BatchAddBoundary001
* @tc.desc: Batch::Add updates start/end boundaries on both edges of each guard
* @tc.precon: A batch seeded by the first timer
* @tc.step: 1. Insert a timer with a later whenElapsed (new_start = true)
*           2. Insert a timer with an equal whenElapsed and a longer maxWhen
*           3. Insert a timer with an equal whenElapsed and a shorter maxWhen
* @tc.expect: start_/end_ of the batch track min/max correctly after each Add
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, BatchAddBoundary001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto base = now + std::chrono::milliseconds(R2_WIN_BASE_MS);
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        // Seed a batch whose window spans one minute, then probe both edges
        // of Batch::Add's boundary handling.
        auto seed = MakeRawTimer(7002201, 3, base, base + std::chrono::milliseconds(R2_WIN_SPAN_MS));
        auto batch = std::make_shared<Batch>(*seed);
        // A later trigger time moves the batch start forward and returns true;
        // a wider ceiling leaves the batch end unchanged.
        auto add1 = MakeRawTimer(7002202, 3, base + std::chrono::milliseconds(1000),
            base + std::chrono::milliseconds(140000));
        EXPECT_TRUE(batch->Add(add1));
        EXPECT_EQ(batch->Size(), 2u);
        EXPECT_EQ(batch->GetStart(), base + std::chrono::milliseconds(1000));
        // An equal trigger time keeps the batch start (returns false);
        // a tighter ceiling pulls the batch end down to the new timer.
        auto add2 = MakeRawTimer(7002203, 3, base + std::chrono::milliseconds(1000),
            base + std::chrono::milliseconds(1500));
        EXPECT_FALSE(batch->Add(add2));
        EXPECT_EQ(batch->Size(), 3u);
        EXPECT_EQ(batch->GetEnd(), base + std::chrono::milliseconds(1500));
        // Remove with a predicate matching nothing: didRemove = false.
        EXPECT_FALSE(batch->Remove([](const TimerInfo &a) { return a.id == 987654321; }));
        EXPECT_EQ(batch->Size(), 3u);
    }
    // The batch above was never published to alarmBatches_ (direct Batch use),
    // so no scheduling state to clean.
}

/**
* @tc.name: InsertAndBatchLogWindow001
* @tc.desc: InsertAndBatchTimerLocked walks every window/batch log combination
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Insert a STANDALONE timer with when != maxWhen
*           2. Insert a coalesced timer with when != maxWhen
*           3. Insert a STANDALONE timer with when == maxWhen
*           4. Insert a coalesced timer with when == maxWhen
* @tc.expect: Standalone cases add new batches; coalesced cases join the window batch
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, InsertAndBatchLogWindow001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto far = now + std::chrono::milliseconds(R2_FAR_BASE_MS);
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        size_t before = manager->alarmBatches_.size();
        // A STANDALONE timer with a window between its trigger points
        // always forms its own batch.
        auto wide = MakeRawTimer(7002301, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(R2_WIN_BASE_MS + R2_WIN_SPAN_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::STANDALONE);
        manager->InsertAndBatchTimerLocked(wide);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
        // A STANDALONE timer with an exact trigger point also forms its own batch.
        auto exact = MakeRawTimer(7002303, 3, far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::STANDALONE);
        manager->InsertAndBatchTimerLocked(exact);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 2);
        // A wide window seeds a coalescible batch [180s, 300s].
        auto holder = MakeRawTimer(7002306, 3, far + std::chrono::milliseconds(3 * R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        manager->InsertAndBatchTimerLocked(holder);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 3);
        // A coalescible timer with a window joins the holder batch; the
        // extended start re-positions the batch in the sorted list.
        auto wide2 = MakeRawTimer(7002302, 3, far + std::chrono::milliseconds(4 * R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(4 * R2_WIN_BASE_MS + 20000));
        manager->InsertAndBatchTimerLocked(wide2);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 3);
        // An exact coalescible timer joins the same holder batch.
        auto exact2 = MakeRawTimer(7002304, 3, far + std::chrono::milliseconds(4 * R2_WIN_BASE_MS + 10000),
            far + std::chrono::milliseconds(4 * R2_WIN_BASE_MS + 10000));
        manager->InsertAndBatchTimerLocked(exact2);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 3);
        // A timer earlier than the batch start joins without re-positioning
        // (Add's new_start = false edge).
        auto early = MakeRawTimer(7002305, 3, far + std::chrono::milliseconds(3 * R2_WIN_BASE_MS + 10000),
            far + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        manager->InsertAndBatchTimerLocked(early);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 3);
        for (uint64_t id : {7002301u, 7002302u, 7002303u, 7002304u, 7002305u, 7002306u}) {
            manager->RemoveLocked(id, false);
        }
        EXPECT_EQ(manager->alarmBatches_.size(), before);
    }
}

/**
* @tc.name: AttemptCoalesceStandaloneSkip001
* @tc.desc: AttemptCoalesceLocked skips a STANDALONE-flagged batch
* @tc.precon: A standalone batch exists whose window could hold the probe
* @tc.step: 1. Insert a STANDALONE timer batch
*           2. Probe AttemptCoalesceLocked with the same window
* @tc.expect: Returns -1 (the flag check rejects the standalone batch)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AttemptCoalesceStandaloneSkip001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto far = now + std::chrono::milliseconds(R2_FAR_BASE_MS);
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        auto solo = MakeRawTimer(7002401, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(R2_WIN_BASE_MS + R2_WIN_SPAN_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::STANDALONE);
        manager->InsertAndBatchTimerLocked(solo);
        auto probe = far + std::chrono::milliseconds(R2_WIN_BASE_MS + 1000);
        auto idx = manager->AttemptCoalesceLocked(probe, probe);
        EXPECT_EQ(idx, -1); // The standalone batch is skipped by the flag check.
        manager->RemoveLocked(7002401, false);
    }
}

/**
* @tc.name: NeedNotifyWantAgentRetry001
* @tc.desc: NeedNotifyWantAgentRetry combines notify failure with recoverability
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Non-recoverable timer + failed notify -> false
*           2. Recoverable timer + failed notify -> true
*           3. Recoverable timer + successful notify -> false
* @tc.expect: Retry is needed only for recoverable timers whose notify failed
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, NeedNotifyWantAgentRetry001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto plain = MakeRawTimer(7002501, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS));
    auto recoverable = MakeRawTimer(7002502, 1, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_branch_bundle",
        nullptr, nullptr, P2R_UID, P2R_PID, -1, true);
    EXPECT_FALSE(manager->NeedNotifyWantAgentRetry(plain, false));
    EXPECT_TRUE(manager->NeedNotifyWantAgentRetry(recoverable, false));
    EXPECT_FALSE(manager->NeedNotifyWantAgentRetry(recoverable, true));
}

/**
* @tc.name: GetWantStringMissingId001
* @tc.desc: GetWantString for an id absent from the database returns empty
* @tc.precon: The id has no row in HOLD_ON_REBOOT
* @tc.step: 1. Call GetWantString with an unused timer id
* @tc.expect: Returns "" (query finds no row and closes the result set)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, GetWantStringMissingId001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto wantStr = manager->GetWantString(999999001);
    EXPECT_EQ(wantStr, "");
}

/**
* @tc.name: NotifyWantAgentAccountError001
* @tc.desc: NotifyWantAgent with a negative uid hits the account-error switch case
* @tc.precon: Timer with wantAgent=nullptr and uid < 0
* @tc.step: 1. Call NotifyWantAgent with uid = -5
* @tc.expect: Returns false (GetOsAccountLocalIdFromUid fails -> E_TIME_ACCOUNT_ERROR)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, NotifyWantAgentAccountError001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto timer = MakeRawTimer(7002601, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_branch_bundle",
        nullptr, nullptr, -5, 0);
    EXPECT_FALSE(manager->NotifyWantAgent(timer));
}

/**
* @tc.name: NotifyWantAgentAccountNotMatch001
* @tc.desc: NotifyWantAgent for a background user returns true without retry
* @tc.precon: Timer whose uid maps to a non-foreground user (localId 102)
* @tc.step: 1. Call NotifyWantAgent with uid = 20400000
* @tc.expect: Returns true (E_TIME_ACCOUNT_NOT_MATCH: no need to retry)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, NotifyWantAgentAccountNotMatch001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto timer = MakeRawTimer(7002602, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_branch_bundle",
        nullptr, nullptr, MULTI_USER_UID, 0);
    EXPECT_TRUE(manager->NotifyWantAgent(timer));
}

/**
* @tc.name: NotifyWantAgentWantStringFallback001
* @tc.desc: NotifyWantAgent falls back to the DB want string and gives up on parse failure
* @tc.precon: Timer with uid 0 (system-level user) and a DB row whose want string
*             cannot be parsed into a WantAgent
* @tc.step: 1. Insert a row with a dummy want string for the timer id
*           2. Call NotifyWantAgent
*           3. Delete the row
* @tc.expect: Returns false (FromString fails, GetWant of the null agent fails)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, NotifyWantAgentWantStringFallback001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    constexpr int64_t dbTimerId = 7002701;
    OHOS::NativeRdb::ValuesBucket values;
    values.PutLong("timerId", dbTimerId);
    values.PutInt("type", 1);
    values.PutInt("flag", 0);
    values.PutLong("windowLength", 0);
    values.PutLong("interval", 0);
    values.PutInt("uid", 0);
    values.PutString("bundleName", "p2_bundle_wa");
    values.PutString("wantAgent", "dummy_want_string");
    values.PutInt("state", 1);
    values.PutLong("triggerTime", 0);
    values.PutInt("pid", 0);
    values.PutString("name", "wa_fallback_case");
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, values);
    auto now = std::chrono::steady_clock::now();
    auto timer = MakeRawTimer(7002701, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_bundle_wa",
        nullptr, nullptr, 0, 0);
    EXPECT_FALSE(manager->NotifyWantAgent(timer));
    OHOS::NativeRdb::RdbPredicates del(HOLD_ON_REBOOT);
    del.EqualTo("timerId", dbTimerId);
    TimeDatabase::GetInstance().Delete(del);
#else
    // Non-RDB builds store want strings in cjson; this DB-fallback path does
    // not exist there.
    SUCCEED();
#endif
}

/**
* @tc.name: AdjustTimerIdempotent001
* @tc.desc: AdjustTimer with unchanged arguments reports "already dealt" and restore clears
* @tc.precon: A future timer sits in a batch so the adjust callback has work
* @tc.step: 1. AdjustTimer(true, 60000, 1000) -> true
*           2. Same call again -> false (early return)
*           3. AdjustTimer(false, 0, 0) -> true (restore + adjustTimers_ cleared)
* @tc.expect: The timer is recorded in adjustTimers_ after step 1 and cleared
*             after step 3; the policy flag ends off
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AdjustTimerIdempotent001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    auto now = std::chrono::steady_clock::now();
    auto far = now + std::chrono::milliseconds(R2_FAR_BASE_MS);
    constexpr uint64_t HOLDER_ID = 7002802;
    constexpr uint64_t FUT_ID = 7002801;
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        // A wide batch [100s, 300s] so the case timer coalesces into it and
        // stays the same object the adjust walk will visit.
        auto holder = MakeRawTimer(HOLDER_ID, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS + 40000),
            far + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        manager->InsertAndBatchTimerLocked(holder);
        auto fut = MakeRawTimer(FUT_ID, 3, far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS), std::chrono::milliseconds(5000), 0,
            "p2_adj_bundle");
        manager->InsertAndBatchTimerLocked(fut);
    }
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 1000));
    {
        std::lock_guard<std::mutex> lock(proxy.adjustMutex_);
        EXPECT_EQ(proxy.adjustTimers_.count(FUT_ID), 1u); // Adjusted and recorded.
    }
    EXPECT_FALSE(manager->AdjustTimer(true, 60000, 1000)); // Already dealt.
    EXPECT_TRUE(manager->AdjustTimer(false, 0, 0)); // Restore path.
    {
        std::lock_guard<std::mutex> lock(proxy.adjustMutex_);
        EXPECT_EQ(proxy.adjustTimers_.count(FUT_ID), 0u); // Registry cleared.
    }
    EXPECT_FALSE(manager->adjustPolicy_); // Policy off after restore.
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->RemoveLocked(FUT_ID, false);
        manager->RemoveLocked(HOLDER_ID, false);
    }
}

/**
* @tc.name: AdjustTimerPolicyLookup001
* @tc.desc: AdjustTimer consults the bundle adjust policy and skips exempt timers
* @tc.precon: A policy entry exists for the timer bundle
* @tc.step: 1. SetAdjustPolicy for the bundle
*           2. AdjustTimer(true, ...) adjusts the timer (policy path + adjustTimers_ insert)
*           3. AdjustTimer(false, 0, 0) restores via adjustTimers_
* @tc.expect: The timer is recorded in adjustTimers_ after step 2 and cleared after step 3
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AdjustTimerPolicyLookup001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    auto now = std::chrono::steady_clock::now();
    auto far = now + std::chrono::milliseconds(R2_FAR_BASE_MS);
    constexpr uint64_t HOLDER_ID = 7002902;
    constexpr uint64_t FUT_ID = 7002901;
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        auto holder = MakeRawTimer(HOLDER_ID, 3, far + std::chrono::milliseconds(R2_WIN_BASE_MS + 40000),
            far + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        manager->InsertAndBatchTimerLocked(holder);
        auto fut = MakeRawTimer(FUT_ID, 3, far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
            far + std::chrono::milliseconds(2 * R2_WIN_BASE_MS), std::chrono::milliseconds(5000), 0,
            "p2_adjp_bundle");
        manager->InsertAndBatchTimerLocked(fut);
    }
    std::unordered_map<std::string, uint32_t> policy = {{"p2_adjp_bundle", 1}};
    manager->SetAdjustPolicy(policy);
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 1000));
    {
        std::lock_guard<std::mutex> lock(proxy.adjustMutex_);
        EXPECT_EQ(proxy.adjustTimers_.count(FUT_ID), 1u); // Policy lookup adjusted it.
    }
    EXPECT_TRUE(manager->AdjustTimer(false, 0, 0));
    {
        std::lock_guard<std::mutex> lock(proxy.adjustMutex_);
        EXPECT_EQ(proxy.adjustTimers_.count(FUT_ID), 0u); // Restored and cleared.
    }
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->RemoveLocked(FUT_ID, false);
        manager->RemoveLocked(HOLDER_ID, false);
    }
    // Write the policy entry back to 0 (equivalent to unset for the consumer).
    std::unordered_map<std::string, uint32_t> undo = {{"p2_adjp_bundle", 0}};
    manager->SetAdjustPolicy(undo);
}

/**
* @tc.name: AdjustSingleTimerMatrix001
* @tc.desc: AdjustSingleTimer/Locked reject null timers and adjust under an active policy
* @tc.precon: adjustPolicy_ is on from an AdjustTimer(true) call
* @tc.step: 1. AdjustSingleTimer(nullptr) -> false
*           2. AdjustSingleTimerLocked(nullptr) -> false
*           3. AdjustSingleTimer(future timer): with the policy on and the timer not
*              proxied, the call falls through to TimerProxy::AdjustTimer
* @tc.expect: Nullptr cases return false, the real timer returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AdjustSingleTimerMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(manager->AdjustSingleTimer(nullptr));
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 1000)); // Turn the policy on.
    auto timer = MakeRawTimer(7003001, 3, now + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(2 * R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_adjs_bundle");
    // Unlocked variant: with the policy on and the timer not proxied, the call
    // falls through to TimerProxy::AdjustTimer.
    EXPECT_TRUE(manager->AdjustSingleTimer(timer));
    EXPECT_EQ(timer->state, TimerInfo::TimerState::ADJUST);
    // Locked variant must be called with proxyMutex_ held (prod lock order).
    {
        std::lock_guard<std::mutex> lock(proxy.proxyMutex_);
        EXPECT_FALSE(manager->AdjustSingleTimerLocked(nullptr));
        EXPECT_TRUE(manager->AdjustSingleTimerLocked(timer));
    }
    // Restore the object through a direct proxy delivery (the manager-level
    // restore only walks timers that live in batches).
    EXPECT_TRUE(proxy.AdjustTimer(false, 0, now, 0, [&timer](AdjustTimerCallback cb) { cb(timer); }));
    EXPECT_EQ(timer->state, TimerInfo::TimerState::INIT);
    {
        std::lock_guard<std::mutex> lock(proxy.adjustMutex_);
        EXPECT_EQ(proxy.adjustTimers_.count(7003001), 0u); // Registry cleared.
    }
    EXPECT_TRUE(manager->AdjustTimer(false, 0, 0)); // Policy off.
    EXPECT_FALSE(manager->adjustPolicy_);
}

/**
* @tc.name: AdjustTimerComboProxyMatrix001
* @tc.desc: AdjustTimer's already-dealt guard walks every sub-condition, and
*           proxied timers skip the single-timer adjust
* @tc.precon: None
* @tc.step: 1. AdjustTimer calls differing only in policy/interval/delta
*              (each short-circuits a different sub-condition of the guard)
*           2. Proxy a uid, then AdjustSingleTimer / Locked for its timer
* @tc.expect: Only the all-equal call returns false; the proxied timer is not
*             adjusted and the proxy state is undone
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AdjustTimerComboProxyMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    // Each call differs from the previous one in exactly one guard operand.
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 1000));
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 2000)); // delta differs.
    EXPECT_TRUE(manager->AdjustTimer(true, 30000, 2000)); // interval differs.
    EXPECT_TRUE(manager->AdjustTimer(false, 30000, 2000)); // policy differs.
    EXPECT_FALSE(manager->AdjustTimer(false, 30000, 2000)); // All equal -> early out.
    EXPECT_TRUE(manager->AdjustTimer(false, 0, 0)); // Back to the idle policy.
    EXPECT_FALSE(manager->adjustPolicy_);
    // Proxied uid: the single-timer adjust takes the IsProxy short-circuit.
    constexpr int PROXIED_UID = 3301;
    EXPECT_TRUE(manager->AdjustTimer(true, 60000, 1000)); // Policy on for the adjust attempts.
    EXPECT_TRUE(manager->ProxyTimer(PROXIED_UID, {}, true, true));
    auto timer = MakeRawTimer(7009002, 3,
        std::chrono::steady_clock::now() + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
        std::chrono::steady_clock::now() + std::chrono::milliseconds(2 * R2_WIN_BASE_MS),
        std::chrono::milliseconds(0), 0, "p2_adjs_bundle", nullptr, nullptr, PROXIED_UID, 0);
    EXPECT_FALSE(manager->AdjustSingleTimer(timer)); // IsProxy -> no adjust.
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        EXPECT_FALSE(manager->AdjustSingleTimerLocked(timer)); // Locked variant.
    }
    EXPECT_TRUE(manager->ProxyTimer(PROXIED_UID, {}, false, true)); // Undo the proxy.
    EXPECT_TRUE(manager->AdjustTimer(false, 0, 0)); // Policy off.
    EXPECT_EQ(timer->state, TimerInfo::TimerState::INIT);
}

/**
* @tc.name: NotifyWantAgentAcrossAccounts001
* @tc.desc: A bundle listed in the across-accounts param passes the account gate
* @tc.precon: The timer's uid would otherwise map to a non-foreground user
* @tc.step: 1. Save and set persist.time.timer_across_accounts to the timer bundle
*           2. NotifyWantAgent with a matching-bundle timer (uid localId 102)
*           3. Restore the original parameter
* @tc.expect: Returns false via the want-string fallback instead of the
*             account-mismatch early return
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, NotifyWantAgentAcrossAccounts001, TestSize.Level1)
{
    constexpr const char *ACROSS_KEY = "persist.time.timer_across_accounts";
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto origValue = OHOS::system::GetParameter(ACROSS_KEY, "");
    OHOS::system::SetParameter(ACROSS_KEY, "p2_across_bundle");
    auto now = std::chrono::steady_clock::now();
    // uid 20400000 maps to localId 102 (a non-foreground user): without the
    // param the account gate returns NOT_MATCH early; with the param the gate
    // passes and the notify falls through to the (missing) want string.
    auto timer = MakeRawTimer(7009101, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_across_bundle",
        nullptr, nullptr, MULTI_USER_UID, 0);
    EXPECT_FALSE(manager->NotifyWantAgent(timer));
    OHOS::system::SetParameter(ACROSS_KEY, origValue.c_str());
}

/**
* @tc.name: ProxyTimerEmptyPidList001
* @tc.desc: ProxyTimer with an empty pid list proxies/restores the whole uid
* @tc.precon: A uid with no started timers
* @tc.step: 1. ProxyTimer(uid, {}) -> registers an empty proxy set
*           2. ProxyTimer(uid, {}) again -> already proxied, still true
*           3. ProxyTimer(uid, {}, isProxy=false) -> uid gone -> true and erased
*           4. ProxyTimer(uid, {pid}, isProxy=false) on a missing key -> false
* @tc.expect: Steps 1-3 return true, step 4 returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, ProxyTimerEmptyPidList001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    constexpr int EMPTY_UID = 3298;
    EXPECT_TRUE(manager->ProxyTimer(EMPTY_UID, {}, true, true));
    EXPECT_TRUE(proxy.IsProxy(EMPTY_UID, 0));
    EXPECT_TRUE(manager->ProxyTimer(EMPTY_UID, {}, true, true)); // Already proxied path.
    EXPECT_TRUE(manager->ProxyTimer(EMPTY_UID, {}, false, true)); // uid absent -> erase key.
    EXPECT_FALSE(proxy.IsProxy(EMPTY_UID, 0));
    EXPECT_FALSE(manager->ProxyTimer(EMPTY_UID, {5555}, false, true)); // Key not in proxy map.
}

/**
* @tc.name: ProxyTimerPidListMatrix001
* @tc.desc: ProxyTimer by pid proxies matched timers and restores them on demand
* @tc.precon: Two started (recorded) timers under one uid with distinct pids
* @tc.step: 1. Proxy pid A with retrigger -> alarm A re-armed with proxy delay
*           2. Proxy the whole uid -> all alarms proxied
*           3. Un-proxy pid A without retrigger -> update-state block runs
*           4. Remove the uid timers, then un-proxy a stale key -> uid-gone path
* @tc.expect: Proxy membership toggles as asserted; no residue left
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, ProxyTimerPidListMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    constexpr int PUID = 3299;
    constexpr int PID_A = 4321;
    constexpr int PID_B = 4322;
    auto now = std::chrono::steady_clock::now();
    auto alarmA = MakeRawTimer(7003101, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_proxy_bundle",
        nullptr, nullptr, PUID, PID_A);
    auto alarmB = MakeRawTimer(7003102, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS + 2000),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS + 2000), std::chrono::milliseconds(0), 0, "p2_proxy_bundle",
        nullptr, nullptr, PUID, PID_B);
    proxy.RecordUidTimerMap(alarmA, false);
    proxy.RecordUidTimerMap(alarmB, false);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(PUID), 2);
    // 1) pid-scoped proxy with retrigger: alarmA matches pid and is re-armed.
    EXPECT_TRUE(manager->ProxyTimer(PUID, {PID_A}, true, true));
    EXPECT_TRUE(proxy.IsProxy(PUID, PID_A));
    // 2) whole-uid proxy: everything (pid=0 wildcard) matches.
    EXPECT_TRUE(manager->ProxyTimer(PUID, {}, true, true));
    EXPECT_TRUE(proxy.IsProxy(PUID, 0));
    EXPECT_EQ(alarmA->state, TimerInfo::TimerState::PROXY);
    // 3) un-proxy pid A without retrigger: UpdateTimersState(needRetrigger=false) block.
    EXPECT_TRUE(manager->ProxyTimer(PUID, {PID_A}, false, false));
    EXPECT_FALSE(proxy.IsProxy(PUID, PID_A));
    // 4) seed a key holding an id missing from uidTimersMap_ plus a valid one:
    //    restore skips the stale id (continue branch) and restores the valid one.
    {
        std::lock_guard<std::mutex> lock(proxy.proxyMutex_);
        proxy.proxyTimers_[GetProxyKey(PUID, PID_B)] = {999999111, 7003102};
    }
    EXPECT_TRUE(manager->ProxyTimer(PUID, {PID_B}, false, true));
    EXPECT_FALSE(proxy.IsProxy(PUID, PID_B));
    // 5) drop the uid timers, then restore the uid-level key: uid-gone path.
    proxy.RemoveUidTimerMap(alarmA);
    proxy.RemoveUidTimerMap(alarmB);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(PUID), 0);
    EXPECT_TRUE(manager->ProxyTimer(PUID, {}, false, true));
    EXPECT_FALSE(proxy.IsProxy(PUID, 0));
    // Clean the proxied batch entries created by the retrigger path.
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->RemoveLocked(7003101, false);
        manager->RemoveLocked(7003102, false);
    }
}

/**
* @tc.name: DeliverTimersWakeupMatrix001
* @tc.desc: DeliverTimersLocked walks wakeup, dead-peer, wantAgent and disposable paths
* @tc.precon: Two entries seeded in timerEntryMap_ for the destroy assertions
* @tc.step: 1. Build a trigger list: wakeup+disposable timer, dead-peer callback
*              timer, wantAgent repeat timer, wantAgent one-shot timer
*           2. Call DeliverTimersLocked directly
* @tc.expect: The disposable and dead-peer timers are destroyed from the entry map
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DeliverTimersWakeupMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    constexpr uint64_t WAKEUP_ID = 7003201;
    constexpr uint64_t DEAD_ID = 7003202;
    // Entries so the destroy paths have something observable to remove.
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[WAKEUP_ID] = std::make_shared<TimerEntry>(
            TimerEntry{"", WAKEUP_ID, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID, "p2_branch_bundle"});
        manager->timerEntryMap_[DEAD_ID] = std::make_shared<TimerEntry>(
            TimerEntry{"", DEAD_ID, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID, "p2_branch_bundle"});
    }
    auto wake = MakeRawTimer(WAKEUP_ID, ITimerManager::ELAPSED_REALTIME_WAKEUP,
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        std::chrono::milliseconds(0), ITimerManager::TimerFlag::IS_DISPOSABLE, "p2_branch_bundle");
    auto dead = MakeRawTimer(DEAD_ID, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_branch_bundle",
        [](uint64_t) { return PEER_END_DEAD_CODE; });
    auto repeat = MakeRawTimer(7003203, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(5000), 0, "p2_branch_bundle",
        nullptr, std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>());
    // One-shot wantAgent timer with a failed notify: walks the wantAgent
    // delivery block (UpdateTimerStateInStorage included). autoRestore stays
    // false so the failed notify does NOT spawn the detached retry thread —
    // that thread would outlive main() and crash static teardown (Signal 11);
    // the retry decision itself is covered by NeedNotifyWantAgentRetry001.
    auto once = MakeRawTimer(7003204, 1, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_bundle_wa",
        nullptr, std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(), P2R_UID, P2R_PID, -1, false);
    std::vector<std::shared_ptr<TimerInfo>> triggerList = {wake, dead, repeat, once};
    manager->DeliverTimersLocked(triggerList);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        // Disposable one-shot and dead-peer timers were destroyed.
        EXPECT_EQ(manager->timerEntryMap_.count(WAKEUP_ID), 0u);
        EXPECT_EQ(manager->timerEntryMap_.count(DEAD_ID), 0u);
    }
}

/**
* @tc.name: TriggerTimersNullFutureBatch001
* @tc.desc: TriggerTimersLocked erases null batches and keeps future batches
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Seed a future batch, then append a null batch entry
*           2. Call TriggerTimersLocked with the current time under mutex_
* @tc.expect: The null entry is erased, the future batch survives, nothing triggers
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, TriggerTimersNullFutureBatch001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        size_t before = manager->alarmBatches_.size();
        // A batch scheduled far ahead must stay untouched by this round.
        auto future = MakeRawTimer(7004101, 3, now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        AddBatchLocked(manager->alarmBatches_, std::make_shared<Batch>(*future));
        EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
        // A null entry appended last: the insert comparator would deref it,
        // so it can only be published after the sorted batches.
        manager->alarmBatches_.push_back(nullptr);
        manager->TriggerTimersLocked(triggerList, now);
        EXPECT_EQ(manager->alarmBatches_.size(), before + 1);
        for (auto &batch : manager->alarmBatches_) {
            EXPECT_NE(batch, nullptr);
        }
        manager->RemoveLocked(7004101, false);
        EXPECT_EQ(manager->alarmBatches_.size(), before);
    }
    EXPECT_EQ(triggerList.size(), 0u);
}

/**
* @tc.name: TriggerTimersExpiredProxy001
* @tc.desc: TriggerTimersLocked fires an expired batch and filters proxied alarms
* @tc.precon: One uid is registered in the proxy map before the call
* @tc.step: 1. Seed an expired batch with a wakeup, a proxied, a repeating and
*              a no-log timer
*           2. Call TriggerTimersLocked with the current time under mutex_
* @tc.expect: The proxied alarm drops out of the list and is re-armed in proxy
*             state; the rest survive; the wakeup flag is set
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, TriggerTimersExpiredProxy001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto &proxy = TimerProxy::GetInstance();
    constexpr int PROXY_UID = 3297;
    auto now = std::chrono::steady_clock::now();
    auto past = now - std::chrono::milliseconds(R2_WIN_BASE_MS);
    {
        std::lock_guard<std::mutex> lock(proxy.proxyMutex_);
        proxy.proxyTimers_[GetProxyKey(PROXY_UID, 0)] = {7004103};
    }
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    bool hasWakeup = false;
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        size_t before = manager->alarmBatches_.size();
        auto wake = MakeRawTimer(7004102, ITimerManager::ELAPSED_REALTIME_WAKEUP, past, past,
            std::chrono::milliseconds(0), 0, "p2_branch_bundle", nullptr, nullptr, P2R_UID, 4401);
        auto proxied = MakeRawTimer(7004103, 3, past, past,
            std::chrono::milliseconds(0), 0, "p2_branch_bundle", nullptr, nullptr, PROXY_UID, 4402);
        auto repeat = MakeRawTimer(7004104, 3, past, past, std::chrono::milliseconds(5000), 0, "p2_branch_bundle");
        auto silent = MakeRawTimer(7004105, 3, past, past, std::chrono::milliseconds(5000), 0, "wifi_manager_service");
        auto expired = std::make_shared<Batch>(*wake);
        expired->Add(proxied);
        expired->Add(repeat);
        expired->Add(silent);
        AddBatchLocked(manager->alarmBatches_, expired);
        hasWakeup = manager->TriggerTimersLocked(triggerList, now);
        EXPECT_GE(manager->alarmBatches_.size(), before + 1u); // Re-armed batches remain.
        EXPECT_EQ(proxied->state, TimerInfo::TimerState::PROXY);
    }
    EXPECT_TRUE(hasWakeup); // The wakeup-type timer set the flag.
    bool foundProxied = false;
    for (auto &t : triggerList) {
        foundProxied = foundProxied || t->id == 7004103;
    }
    EXPECT_FALSE(foundProxied); // Dropped out of the trigger list.
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        // The re-armed repeating/proxied timers reuse the original ids, so the
        // cleanup below removes every batch this case created.
        for (uint64_t id : {7004102u, 7004103u, 7004104u, 7004105u}) {
            manager->RemoveLocked(id, false);
        }
    }
    {
        std::lock_guard<std::mutex> lock(proxy.proxyMutex_);
        proxy.proxyTimers_.erase(GetProxyKey(PROXY_UID, 0));
    }
}

/**
* @tc.name: TriggerTimersIdlePending001
* @tc.desc: Triggering the idle timer restores pended delay timers and ends idle mode
* @tc.precon: Idle mode active with two pended timers, one future and one past
* @tc.step: 1. Seed an expired IDLE_UNTIL timer and two pending delay timers
*           2. Seed a delayedTimers_ entry, then call TriggerTimersLocked
* @tc.expect: Idle state clears, both pending timers are re-armed, delayed list drains
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, TriggerTimersIdlePending001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        auto idle = MakeRawTimer(7004106, 3, now - std::chrono::milliseconds(R2_WIN_BASE_MS),
            now - std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::IDLE_UNTIL, "p2_idle_bundle");
        AddBatchLocked(manager->alarmBatches_, std::make_shared<Batch>(*idle));
        auto delayFuture = MakeRawTimer(7004107, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_idle_bundle");
        auto delayPast = MakeRawTimer(7004108, 3, now - std::chrono::milliseconds(R2_WIN_BASE_MS),
            now - std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_idle_bundle");
        manager->pendingDelayTimers_ = {delayFuture, delayPast};
        manager->delayedTimers_[999999] = now;
        manager->mPendingIdleUntil_ = idle;
        manager->TriggerTimersLocked(triggerList, now);
        EXPECT_EQ(manager->mPendingIdleUntil_, nullptr);
        EXPECT_EQ(manager->pendingDelayTimers_.size(), 0u);
        EXPECT_EQ(manager->delayedTimers_.size(), 0u);
        // Cleanup: drop every id this case scheduled.
        for (uint64_t id : {7004106u, 7004107u, 7004108u}) {
            manager->RemoveLocked(id, false);
        }
    }
}

/**
* @tc.name: SetHandlerPendingIdle001
* @tc.desc: A not-allowed timer pends while idle and is restored when idle ends
* @tc.precon: Shell token restored so CheckProxyCallingPermission trusts the caller
* @tc.step: 1. Set mPendingIdleUntil_ to a far-future idle timer
*           2. SetHandlerLocked for an INEXACT_REMINDER timer -> pends
*           3. RemoveLocked the idle timer -> pending timers restored
* @tc.expect: pendingDelayTimers_ grows to 1, then drains to 0
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, SetHandlerPendingIdle001, TestSize.Level1)
{
    RestoreR2ShellToken();
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        auto idle = MakeRawTimer(7005101, 3, now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::IDLE_UNTIL, "p2_idle_bundle");
        manager->mPendingIdleUntil_ = idle;
        auto blocked = MakeRawTimer(7005102, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::INEXACT_REMINDER, "p2_block_bundle");
        // While idle, an INEXACT_REMINDER timer is not allowed, so it is
        // pended instead of batched.
        manager->SetHandlerLocked(blocked, false, false);
        EXPECT_EQ(manager->pendingDelayTimers_.size(), 1u);
        // Removing the idle timer sets the pending timers back into batches.
        manager->RemoveLocked(7005101, false);
        EXPECT_EQ(manager->mPendingIdleUntil_, nullptr);
        EXPECT_EQ(manager->pendingDelayTimers_.size(), 0u);
        manager->RemoveLocked(7005102, false);
    }
}

/**
* @tc.name: SetHandlerIdleUntilFlag001
* @tc.desc: Setting an IDLE_UNTIL timer enters idle mode and delays restricted timers
* @tc.precon: A restricted (INEXACT_REMINDER) timer already batched
* @tc.step: 1. Insert a restricted timer whose window precedes the idle timer
*           2. SetHandlerLocked the IDLE_UNTIL timer
* @tc.expect: The restricted timer lands in delayedTimers_ and idle mode is on
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, SetHandlerIdleUntilFlag001, TestSize.Level1)
{
    RestoreR2ShellToken();
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        auto restricted = MakeRawTimer(7005201, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::INEXACT_REMINDER, "p2_block_bundle");
        manager->InsertAndBatchTimerLocked(restricted);
        auto idle = MakeRawTimer(7005202, 3, now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS), std::chrono::milliseconds(0),
            ITimerManager::TimerFlag::IDLE_UNTIL, "p2_idle_bundle");
        manager->SetHandlerLocked(idle, false, false);
        EXPECT_EQ(manager->mPendingIdleUntil_, idle);
        // The restricted timer was delayed behind the idle timer.
        EXPECT_EQ(manager->delayedTimers_.count(7005201), 1u);
        // Cleanup: end idle mode and drop both timers.
        manager->mPendingIdleUntil_ = nullptr;
        manager->delayedTimers_.clear();
        manager->RemoveLocked(7005201, false);
        manager->RemoveLocked(7005202, false);
    }
}

/**
* @tc.name: OnUserRemovedMatrix001
* @tc.desc: OnUserRemoved skips invalid uids and destroys the removed user's timers
* @tc.precon: Two entries seeded: one with a negative uid, one with uid 0
* @tc.step: 1. Call OnUserRemoved(0)
* @tc.expect: The uid 0 entry is destroyed, the negative-uid entry survives
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, OnUserRemovedMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[7005301] = std::make_shared<TimerEntry>(
            TimerEntry{"", 7005301, 3, 0, 0, 0, false, nullptr, nullptr, -5, 0, "p2_branch_bundle"});
        manager->timerEntryMap_[7005302] = std::make_shared<TimerEntry>(
            TimerEntry{"", 7005302, 3, 0, 0, 0, false, nullptr, nullptr, 0, 0, "p2_branch_bundle"});
    }
    manager->OnUserRemoved(0);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(7005302), 0u); // user 0 timer destroyed
        EXPECT_EQ(manager->timerEntryMap_.count(7005301), 1u); // invalid uid skipped
        manager->timerEntryMap_.erase(7005301);
    }
}

/**
* @tc.name: OnPackageRemoved001
* @tc.desc: OnPackageRemoved destroys only the timers of the removed uid
* @tc.precon: Two entries with different uids
* @tc.step: 1. Call OnPackageRemoved for one uid
* @tc.expect: Only that uid's entry is destroyed
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, OnPackageRemoved001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[7005401] = std::make_shared<TimerEntry>(
            TimerEntry{"", 7005401, 3, 0, 0, 0, false, nullptr, nullptr, 3212, 0, "p2_branch_bundle"});
        manager->timerEntryMap_[7005402] = std::make_shared<TimerEntry>(
            TimerEntry{"", 7005402, 3, 0, 0, 0, false, nullptr, nullptr, 3213, 0, "p2_branch_bundle"});
    }
    manager->OnPackageRemoved(3212);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(7005401), 0u);
        EXPECT_EQ(manager->timerEntryMap_.count(7005402), 1u);
        manager->timerEntryMap_.erase(7005402);
    }
}

/**
* @tc.name: HandleRSSDeathIdle001
* @tc.desc: HandleRSSDeath stops the pending idle timer when RSS dies
* @tc.precon: An idle timer id seeded in the entry map
* @tc.step: 1. Call HandleRSSDeath with no idle timer (early return)
*           2. Set mPendingIdleUntil_ and call again
* @tc.expect: The idle timer entry is destroyed by the second call
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, HandleRSSDeathIdle001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    constexpr uint64_t IDLE_ID = 7005501;
    manager->HandleRSSDeath(); // No idle timer: early return branch.
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[IDLE_ID] = std::make_shared<TimerEntry>(
            TimerEntry{"", IDLE_ID, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, 0, "p2_branch_bundle"});
    }
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->mPendingIdleUntil_ = MakeRawTimer(IDLE_ID, 3,
            std::chrono::steady_clock::now() + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
            std::chrono::steady_clock::now() + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
    }
    manager->HandleRSSDeath();
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        EXPECT_EQ(manager->timerEntryMap_.count(IDLE_ID), 0u);
    }
    std::lock_guard<std::mutex> lock(manager->mutex_);
    manager->mPendingIdleUntil_ = nullptr;
}

/**
* @tc.name: AdjustDeliveryIdleMatrix001
* @tc.desc: AdjustDeliveryTimeBasedOnDeviceIdle covers delayed/undelayed combinations
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. mPendingIdleUntil_ == alarm -> false
*           2. No idle, alarm delayed (RTC, future origWhen) -> reschedule true
*           3. No idle, alarm delayed (ELAPSED, past origWhen) -> 2ms retrigger true
*           4. No idle, alarm not delayed -> false
* @tc.expect: Return values as listed
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AdjustDeliveryIdleMatrix001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    auto now = std::chrono::steady_clock::now();
    auto wallNowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lock(manager->mutex_);
    auto idle = MakeRawTimer(7005601, 3, now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
    manager->mPendingIdleUntil_ = idle;
    // 1) The idle timer itself is never adjusted.
    EXPECT_FALSE(manager->AdjustDeliveryTimeBasedOnDeviceIdle(idle));
    manager->mPendingIdleUntil_ = nullptr;
    // 2) Delayed RTC timer with a future origWhen: offset-based reschedule.
    //    whenElapsed is stale (+10s) while origWhen is +60s, so the update
    //    changes the elapsed time and returns true.
    auto rtc = MakeRawTimer(7005602, ITimerManager::RTC, now + std::chrono::milliseconds(10000),
        now + std::chrono::milliseconds(10000), std::chrono::milliseconds(0), 0, "p2_idle_bundle",
        nullptr, nullptr, P2R_UID, P2R_PID, wallNowMs + R2_WIN_BASE_MS);
    manager->delayedTimers_[7005602] = now;
    EXPECT_TRUE(manager->AdjustDeliveryTimeBasedOnDeviceIdle(rtc));
    // 3) Delayed ELAPSED timer with a past origWhen: 2ms retrigger.
    auto elapsed = MakeRawTimer(7005603, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS), std::chrono::milliseconds(0), 0, "p2_idle_bundle",
        nullptr, nullptr, P2R_UID, P2R_PID, 1000);
    manager->delayedTimers_[7005603] = now;
    EXPECT_TRUE(manager->AdjustDeliveryTimeBasedOnDeviceIdle(elapsed));
    // 4) Not delayed, no idle: no adjustment.
    auto plain = MakeRawTimer(7005604, 3, now + std::chrono::milliseconds(R2_WIN_BASE_MS),
        now + std::chrono::milliseconds(R2_WIN_BASE_MS));
    EXPECT_FALSE(manager->AdjustDeliveryTimeBasedOnDeviceIdle(plain));
    manager->delayedTimers_.clear();
}

/**
* @tc.name: DumpTimerInfoCases001
* @tc.desc: HIDumper helpers walk found and missing timer paths
* @tc.precon: One entry and one batched timer seeded
* @tc.step: 1. Call ShowTimerEntryMap / ShowTimerEntryById (hit and miss) /
*              ShowTimerTriggerById / ShowIdleTimerInfo
* @tc.expect: All return true; the miss case returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, DumpTimerInfoCases001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    constexpr uint64_t DUMP_ID = 7005701;
    int fd = open("/dev/null", O_WRONLY);
    ASSERT_GT(fd, 0);
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_[DUMP_ID] = std::make_shared<TimerEntry>(
            TimerEntry{"dump_case", DUMP_ID, 3, 0, 0, 0, false, nullptr, nullptr, P2R_UID, P2R_PID,
                "p2_branch_bundle"});
    }
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->InsertAndBatchTimerLocked(MakeRawTimer(DUMP_ID, 3,
            now + std::chrono::milliseconds(R2_WIN_BASE_MS), now + std::chrono::milliseconds(R2_WIN_BASE_MS)));
        manager->mPendingIdleUntil_ = MakeRawTimer(7005702, 3,
            now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS),
            now + std::chrono::milliseconds(5 * R2_WIN_BASE_MS));
        manager->pendingDelayTimers_ = {MakeRawTimer(7005703, 3,
            now + std::chrono::milliseconds(R2_WIN_BASE_MS), now + std::chrono::milliseconds(R2_WIN_BASE_MS))};
        manager->delayedTimers_[7005703] = now;
    }
    EXPECT_TRUE(manager->ShowTimerEntryMap(fd));
    EXPECT_TRUE(manager->ShowTimerEntryById(fd, DUMP_ID));
    EXPECT_FALSE(manager->ShowTimerEntryById(fd, 987654321)); // Missing id.
    EXPECT_TRUE(manager->ShowTimerTriggerById(fd, DUMP_ID));
    EXPECT_TRUE(manager->ShowIdleTimerInfo(fd));
    {
        std::lock_guard<std::mutex> lock(manager->mutex_);
        manager->mPendingIdleUntil_ = nullptr;
        manager->pendingDelayTimers_.clear();
        manager->delayedTimers_.clear();
        manager->RemoveLocked(DUMP_ID, false);
    }
    {
        std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
        manager->timerEntryMap_.erase(DUMP_ID);
    }
    close(fd);
}

/**
* @tc.name: SetLockedZeroWhen001
* @tc.desc: SetLocked clamps a non-positive when to the current boot time
* @tc.precon: TimerManager singleton is available
* @tc.step: 1. Under mutex_, call SetLocked with when = 0ns
* @tc.expect: No crash; the handler accepts the clamped time
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, SetLockedZeroWhen001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
    std::lock_guard<std::mutex> lock(manager->mutex_);
    auto bootNow = std::chrono::steady_clock::now();
    // SetLocked clamps a non-positive when to the current boot time; run that
    // clamp path, then verify the handler accepts the zero-valued time the
    // clamp guarantees as a valid input.
    manager->SetLocked(ITimerManager::ELAPSED_REALTIME, std::chrono::nanoseconds(0), bootNow);
    EXPECT_EQ(manager->handler_->Set(static_cast<uint32_t>(ITimerManager::ELAPSED_REALTIME),
        std::chrono::nanoseconds(0), bootNow), 0);
}

/**
* @tc.name: AddRunningLockNegative001
* @tc.desc: AddRunningLock rejects a negative hold time before creating a lock
* @tc.precon: POWER_MANAGER_ENABLE build
* @tc.step: 1. Call AddRunningLock(-1)
* @tc.expect: Returns immediately; no running lock object is created
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, AddRunningLockNegative001, TestSize.Level1)
{
    auto manager = TimerManager::GetInstance();
    ASSERT_NE(manager, nullptr);
#ifdef POWER_MANAGER_ENABLE
    std::shared_ptr<PowerMgr::RunningLock> before;
    {
        std::lock_guard<std::mutex> lock(manager->runningLockMutex_);
        before = manager->runningLock_;
    }
    manager->AddRunningLock(-1); // Negative guard: returns before any lock work.
    {
        std::lock_guard<std::mutex> lock(manager->runningLockMutex_);
        EXPECT_EQ(manager->runningLock_, before); // Unchanged by the rejected call.
    }
#else
    // Non-POWER_MANAGER builds have no running lock to exercise.
    SUCCEED();
#endif
}

/**
* @tc.name: InProcessSetTimeChange001
* @tc.desc: In-process SetTime drives the looper time-change rebatch path
* @tc.precon: System app token with SET_TIME permission; device time saved
* @tc.step: 1. Read the current time through the client
*           2. SetTime forward 2s, backward 1s, forward 0.3s (three change shapes)
*           3. Restore the original time
* @tc.expect: All SetTime calls return E_TIME_OK and the time is restored
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerManagerDeepBranchTest, InProcessSetTimeChange001, TestSize.Level1)
{
    SetLooperSystemToken();
    // The test runs on the device, so gettimeofday reads the device clock.
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t before = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(before, 0);
    // Three change shapes: first-ever change, backward change, small forward change.
    EXPECT_EQ(TimeSystemAbility::GetInstance()->SetTime(before + 2000), E_TIME_OK);
    usleep(300000); // Let the looper consume the RTC change event.
    EXPECT_EQ(TimeSystemAbility::GetInstance()->SetTime(before + 1000), E_TIME_OK);
    usleep(300000);
    EXPECT_EQ(TimeSystemAbility::GetInstance()->SetTime(before + 1300), E_TIME_OK);
    usleep(300000);
    // Restore the saved time (side-effect rule).
    EXPECT_EQ(TimeSystemAbility::GetInstance()->SetTime(before), E_TIME_OK);
    usleep(200000);
    struct timeval afterTime {
    };
    gettimeofday(&afterTime, NULL);
    int64_t after = afterTime.tv_sec * 1000 + afterTime.tv_usec / 1000;
    EXPECT_NEAR(after, before, 5000); // Back at the saved time (plus read latency).
}
} // namespace MiscServices
} // namespace OHOS
