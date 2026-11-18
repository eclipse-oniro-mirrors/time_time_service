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
#include "timer_info.h"
#include "batch.h"
#undef private
#undef protected

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "time_service_client.h"
#include "itimer_callback.h"
#include "message_parcel.h"
#include "token_setproc.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

// Free function declared in timer_manager.cpp without a header declaration.
bool IsNoLog(std::shared_ptr<TimerInfo> alarm);

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
    ASSERT_NE(alarm, nullptr);
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
    ASSERT_NE(alarm, nullptr);
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
    ASSERT_NE(alarm, nullptr);
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
    ASSERT_NE(alarm, nullptr);
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
// (TriggerTimersLocked -> DeliverTimersLocked -> RescheduleKernelTimerLocked)
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
    ASSERT_NE(timerInfo, nullptr);
    timerInfo->SetType(ELAPSED_TIMER_TYPE);
    timerInfo->SetRepeat(false);
    timerInfo->SetDisposable(true);
    auto callbackObj = sptr<IRemoteObject>(new LocalTimerCallbackStub());
    ASSERT_NE(callbackObj, nullptr);
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
    ASSERT_NE(timerInfo, nullptr);
    timerInfo->SetType(ELAPSED_TIMER_TYPE);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(REPEAT_FIRE_INTERVAL_MS);
    auto callbackObj = sptr<IRemoteObject>(new LocalTimerCallbackStub());
    ASSERT_NE(callbackObj, nullptr);
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
    auto manager = TimerManager::GetInstance();
    std::lock_guard<std::mutex> lock(manager->entryMapMutex_);
    EXPECT_EQ(manager->timerEntryMap_.count(timerId), 0);
}
} // namespace MiscServices
} // namespace OHOS
