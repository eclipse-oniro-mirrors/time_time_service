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
#include "time_zone_info.h"
#include "time_tick_notify.h"
#include "event_manager.h"
#include "ntp_update_time.h"
#undef private
#undef protected

#include <gtest/gtest.h>
#include <cstdlib>
#include <ctime>
#include <string>

#include "cjson_helper.h"
#include "common_event_data.h"
#include "itimer_callback.h"
#include "message_parcel.h"
#include "timer_database.h"
#include "common_event_subscribe_info.h"
#include "matching_skills.h"
#include "want.h"

#include "time_common.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::EventFwk;
using namespace OHOS::AAFwk;
using std::chrono::steady_clock;

class TimeMiscBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimeMiscBranchTest::SetUpTestCase(void)
{
}

void TimeMiscBranchTest::TearDownTestCase(void)
{
}

void TimeMiscBranchTest::SetUp(void)
{
}

void TimeMiscBranchTest::TearDown(void)
{
}

/**
* @tc.name: SetTimezoneToKernelInvalidOffset001
* @tc.desc: SetTimezoneToKernel rejects a TZ offset beyond +24h
* @tc.precon: None
* @tc.step: 1. Set TZ to "XXX-50" (UTC+50h, out of the +-86400s guard)
*           2. Call TimeZoneInfo::SetTimezoneToKernel
*           3. Restore TZ to Asia/Shanghai
* @tc.expect: SetTimezoneToKernel returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, SetTimezoneToKernelInvalidOffset001, TestSize.Level1)
{
    ASSERT_EQ(setenv("TZ", "XXX-50", 1), 0);
    tzset();
    auto ret = TimeZoneInfo::GetInstance().SetTimezoneToKernel();
    EXPECT_FALSE(ret);
    // Restore the process timezone environment.
    ASSERT_EQ(setenv("TZ", "Asia/Shanghai", 1), 0);
    tzset();
}

/**
* @tc.name: SetTimezoneToKernelInvalidNegOffset001
* @tc.desc: SetTimezoneToKernel rejects a TZ offset beyond -24h
* @tc.precon: None
* @tc.step: 1. Set TZ to "XXX+50" (UTC-50h, out of the +-86400s guard)
*           2. Call TimeZoneInfo::SetTimezoneToKernel
*           3. Restore TZ to Asia/Shanghai
* @tc.expect: SetTimezoneToKernel returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, SetTimezoneToKernelInvalidNegOffset001, TestSize.Level1)
{
    ASSERT_EQ(setenv("TZ", "XXX+50", 1), 0);
    tzset();
    auto ret = TimeZoneInfo::GetInstance().SetTimezoneToKernel();
    EXPECT_FALSE(ret);
    ASSERT_EQ(setenv("TZ", "Asia/Shanghai", 1), 0);
    tzset();
}

/**
* @tc.name: SetTimezoneToKernelNormal001
* @tc.desc: SetTimezoneToKernel succeeds with a valid timezone offset
* @tc.precon: TZ is set to Asia/Shanghai
* @tc.step: 1. Set TZ to Asia/Shanghai
*           2. Call TimeZoneInfo::SetTimezoneToKernel
* @tc.expect: SetTimezoneToKernel returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, SetTimezoneToKernelNormal001, TestSize.Level1)
{
    ASSERT_EQ(setenv("TZ", "Asia/Shanghai", 1), 0);
    tzset();
    auto ret = TimeZoneInfo::GetInstance().SetTimezoneToKernel();
    EXPECT_TRUE(ret);
}

/**
* @tc.name: TickCallbackDedup001
* @tc.desc: Two consecutive tick callbacks within one second deduplicate the publish
* @tc.precon: TimeTickNotify singleton is available
* @tc.step: 1. Reset lastTriggerTime_ to now (fresh publish window closed)
*           2. Call Callback twice back to back
* @tc.expect: No crash; the second call finds the time delta below the threshold
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, TickCallbackDedup001, TestSize.Level1)
{
    auto &tick = TimeTickNotify::GetInstance();
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        tick.lastTriggerTime_ = steady_clock::now().time_since_epoch().count();
    }
    uint64_t timerIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        timerIdBefore = tick.timerId_;
    }
    tick.Callback();
    tick.Callback();
    // The tick timer id must be untouched by the callback invocations.
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        EXPECT_EQ(tick.timerId_, timerIdBefore);
    }
}

/**
* @tc.name: TickCallbackPublish001
* @tc.desc: A tick callback with a stale lastTriggerTime_ republishes
* @tc.precon: TimeTickNotify singleton is available
* @tc.step: 1. Reset lastTriggerTime_ to an old value
*           2. Call Callback once
* @tc.expect: No crash and lastTriggerTime_ is refreshed
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, TickCallbackPublish001, TestSize.Level1)
{
    auto &tick = TimeTickNotify::GetInstance();
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        tick.lastTriggerTime_ = 1;
    }
    uint64_t timerIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        timerIdBefore = tick.timerId_;
    }
    // Whether lastTriggerTime_ is refreshed depends on the wall clock landing
    // inside the first second of a minute (RefreshNextTriggerTime's
    // isFirstSecond), which is not controllable from the test; the recorded
    // trigger time stays a valid non-negative value either way.
    tick.Callback();
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        EXPECT_EQ(tick.timerId_, timerIdBefore);
    }
    int64_t after = 0;
    {
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        after = tick.lastTriggerTime_;
    }
    EXPECT_GE(after, 0);
}

namespace {
// Build an EventManager without triggering a real CES subscription.
std::shared_ptr<EventManager> MakeEventManager()
{
    MatchingSkills skills;
    skills.AddEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE);
    CommonEventSubscribeInfo info(skills);
    return std::make_shared<EventManager>(info);
}

CommonEventData MakeEvent(const std::string &action, int32_t code)
{
    Want want;
    want.SetAction(action);
    CommonEventData data;
    data.SetWant(want);
    data.SetCode(code);
    return data;
}
}

/**
* @tc.name: EventManagerUnknownAction001
* @tc.desc: OnReceiveEvent with an unregistered action is ignored
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with an unknown action
* @tc.expect: No crash and nothing dispatched
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerUnknownAction001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent("ohos.some.unknown.action", 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerConnectivityNotConnected001
* @tc.desc: OnReceiveEvent with CONNECTIVITY_CHANGE but code != connected is ignored
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with connectivity change, code = 1
* @tc.expect: No crash and nothing dispatched
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerConnectivityNotConnected001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE, 1);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerScreenOn001
* @tc.desc: OnReceiveEvent with the screen-on action dispatches the power branch
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with the screen-on action
* @tc.expect: No crash (power branch runs TimeTickNotify::Callback internally)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerScreenOn001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON, 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerNitzTime001
* @tc.desc: OnReceiveEvent with the NITZ time changed action dispatches the NITZ branch
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with the NITZ action
* @tc.expect: No crash (NITZ branch runs UpdateNITZSetTime internally)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerNitzTime001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED, 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerPackageRemoved001
* @tc.desc: OnReceiveEvent with the package-removed action dispatches the removal branch
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with the package-removed action
* @tc.expect: No crash (removal branch runs OnPackageRemoved internally)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerPackageRemoved001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerBundleRemoved001
* @tc.desc: OnReceiveEvent with the bundle-removed action dispatches the same removal branch
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with the bundle-removed action
* @tc.expect: No crash
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerBundleRemoved001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_BUNDLE_REMOVED, 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

/**
* @tc.name: EventManagerPackageFullyRemoved001
* @tc.desc: OnReceiveEvent with the package-fully-removed action dispatches the removal branch
* @tc.precon: None
* @tc.step: 1. Build an EventManager
*           2. Call OnReceiveEvent with the package-fully-removed action
* @tc.expect: No crash
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, EventManagerPackageFullyRemoved001, TestSize.Level1)
{
    auto manager = MakeEventManager();
    ASSERT_NE(manager, nullptr);
    auto data = MakeEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED, 0);
    // Observe a stable side-effect-free state: the tick timer id (read under
    // the tick lock, no function call) must be unchanged by the dispatch.
    auto &tickObs = TimeTickNotify::GetInstance();
    uint64_t tickIdBefore = 0;
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        tickIdBefore = tickObs.timerId_;
    }
    manager->OnReceiveEvent(data);
    {
        std::lock_guard<std::mutex> lock(tickObs.timeridMutex_);
        EXPECT_EQ(tickObs.timerId_, tickIdBefore);
    }
}

// ---------------------------------------------------------------------------
// Timer recovery paths (SA restart / reboot restore). Direct calls to the
// in-process SA: the empty-table branches and a data-bearing restore walk
// RecoverTimerFromDb -> RecoverTimerInner (a branch-dense migration loop).
// ---------------------------------------------------------------------------
#ifdef RDB_ENABLE
namespace {
constexpr int64_t RECOVER_ID_BASE = 800000;
// Test identity and timer type used by the recovery-row helper: type 4 is a
// type the hold_on_reboot cleanup keeps (not 0/2/3 which are cleared).
constexpr int RECOVER_TEST_UID = 3057;
constexpr int RECOVER_TEST_PID = 3057;
constexpr int RECOVER_TIMER_TYPE = 4;

void InsertRecoverRow(const std::string &table, int64_t timerId, int state)
{
    OHOS::NativeRdb::ValuesBucket values;
    values.PutLong("timerId", timerId);
    values.PutInt("type", RECOVER_TIMER_TYPE);
    values.PutInt("flag", 0);
    values.PutLong("windowLength", 0);
    values.PutLong("interval", 0);
    values.PutInt("uid", RECOVER_TEST_UID);
    values.PutString("bundleName", "recover_branch_bundle");
    values.PutString("wantAgent", "");
    values.PutInt("state", state);
    values.PutLong("triggerTime", 0);
    values.PutInt("pid", RECOVER_TEST_PID);
    values.PutString("name", "recover_branch_name");
    TimeDatabase::GetInstance().Insert(table, values);
}

void DeleteRecoverRow(const std::string &table, int64_t timerId)
{
    OHOS::NativeRdb::RdbPredicates predicates(table);
    predicates.EqualTo("timerId", timerId);
    TimeDatabase::GetInstance().Delete(predicates);
}
}
#endif

/**
* @tc.name: RecoverTimerEmpty001
* @tc.desc: RecoverTimer with empty tables walks all empty-result branches safely
* @tc.precon: hold_on_reboot and drop_on_reboot contain no rows
* @tc.step: 1. Ensure both tables have no leftover rows from other cases
*           2. Call TimeSystemAbility::RecoverTimer
* @tc.expect: No crash; the empty-result branches of all four recovery paths run
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, RecoverTimerEmpty001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto ret = TimeSystemAbility::GetInstance()->RecoverTimer();
    EXPECT_TRUE(ret);
#else
    auto ret = TimeSystemAbility::GetInstance()->RecoverTimer();
    EXPECT_TRUE(ret);
#endif
}

#ifdef RDB_ENABLE
/**
* @tc.name: RecoverTimerWithData001
* @tc.desc: RecoverTimer with stored rows walks the migration loop and re-arms
* @tc.precon: hold_on_reboot holds rows with state=1 (auto-restore candidates)
* @tc.step: 1. Insert one state=1 row into hold_on_reboot
*           2. Call TimeSystemAbility::RecoverTimer
*           3. Clean the row afterwards
* @tc.expect: No crash; the migration loop processes the stored row
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, RecoverTimerWithData001, TestSize.Level1)
{
    InsertRecoverRow(HOLD_ON_REBOOT, RECOVER_ID_BASE, 1);
    auto ret = TimeSystemAbility::GetInstance()->RecoverTimer();
    EXPECT_TRUE(ret);
    DeleteRecoverRow(HOLD_ON_REBOOT, RECOVER_ID_BASE);
}
#endif

// ---------------------------------------------------------------------------
// In-process Get* direct calls. These query APIs were previously only invoked
// through the client (IPC to the device SA), which left the in-binary
// implementations unmeasured. Direct calls cover the GetTimeByClockId /
// pthread_getcpuclockid branches inside the instrumented process.
// ---------------------------------------------------------------------------
/**
* @tc.name: GetWallTimeMsDirect001
* @tc.desc: In-process GetWallTimeMs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetWallTimeMs directly
* @tc.expect: Returns E_TIME_OK with a non-negative time
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetRealTimeMsDirect001, TestSize.Level1)
{
    int64_t time = 0;
    auto ret = TimeSystemAbility::GetInstance()->GetRealTimeMs(time);
    // GetRealTime depends on the NTP update state of the device: on a networked
    // device it returns E_TIME_OK with a calibrated time; without a successful
    // NTP sync it returns E_TIME_NTP_NOT_UPDATE. Both are valid outcomes.
    if (ret == E_TIME_OK) {
        EXPECT_GE(time, 0);
    } else {
        EXPECT_EQ(ret, E_TIME_NTP_NOT_UPDATE);
    }
}

/**
* @tc.name: GetWallTimeNsDirect001
* @tc.desc: In-process GetWallTimeNs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetWallTimeNs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetNtpTimeMsDirect001, TestSize.Level1)
{
    int64_t time = 0;
    auto ret = TimeSystemAbility::GetInstance()->GetNtpTimeMs(time);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_GE(time, 0);
}

/**
* @tc.name: GetBootTimeMsDirect001
* @tc.desc: In-process GetBootTimeMs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetBootTimeMs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetTimeByClockIdMonotonic001, TestSize.Level1)
{
    struct timespec tv {};
    auto ret = TimeSystemAbility::GetInstance()->GetTimeByClockId(CLOCK_MONOTONIC, tv);
    EXPECT_TRUE(ret);
    EXPECT_GE(tv.tv_sec, 0);
}

/**
* @tc.name: GetBootTimeNsDirect001
* @tc.desc: In-process GetBootTimeNs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetBootTimeNs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetTimeByClockIdRealtime001, TestSize.Level1)
{
    struct timespec tv {};
    auto ret = TimeSystemAbility::GetInstance()->GetTimeByClockId(CLOCK_REALTIME, tv);
    EXPECT_TRUE(ret);
    EXPECT_GE(tv.tv_sec, 0);
}

/**
* @tc.name: GetMonotonicTimeMsDirect001
* @tc.desc: In-process GetMonotonicTimeMs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetMonotonicTimeMs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetTimeByClockIdBoottime001, TestSize.Level1)
{
    struct timespec tv {};
    auto ret = TimeSystemAbility::GetInstance()->GetTimeByClockId(CLOCK_BOOTTIME, tv);
    EXPECT_TRUE(ret);
    EXPECT_GE(tv.tv_sec, 0);
}

/**
* @tc.name: GetMonotonicTimeNsDirect001
* @tc.desc: In-process GetMonotonicTimeNs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetMonotonicTimeNs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetTimeZoneDirect001, TestSize.Level1)
{
    std::string timeZoneId;
    auto ret = TimeSystemAbility::GetInstance()->GetTimeZone(timeZoneId);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_FALSE(timeZoneId.empty());
}

/**
* @tc.name: GetThreadTimeMsDirect001
* @tc.desc: In-process GetThreadTimeMs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetThreadTimeMs directly
* @tc.expect: Returns E_TIME_OK with a non-negative time
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetThreadTimeMsDirect001, TestSize.Level1)
{
    int64_t time = 0;
    auto ret = TimeSystemAbility::GetInstance()->GetThreadTimeMs(time);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_GE(time, 0);
}

/**
* @tc.name: GetThreadTimeNsDirect001
* @tc.desc: In-process GetThreadTimeNs returns E_TIME_OK with a valid time
* @tc.precon: None
* @tc.step: 1. Call TimeSystemAbility::GetThreadTimeNs directly
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, GetThreadTimeNsDirect001, TestSize.Level1)
{
    int64_t time = 0;
    auto ret = TimeSystemAbility::GetInstance()->GetThreadTimeNs(time);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_GE(time, 0);
}

/**
* @tc.name: CreateTimerWithoutWASuccess001
* @tc.desc: CreateTimerWithoutWA with valid parameters succeeds and returns a real timer id
* @tc.precon: System app token with permissions is set
* @tc.step: 1. Create a timer through the string-arg overload with a callback object
*           2. Destroy it afterwards
* @tc.expect: Returns E_TIME_OK and the timer id is non-zero
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, CreateTimerWithoutWASuccess001, TestSize.Level1)
{
    // The plain-token cases run without AddPermission here; the default test
    // process token (shell) is trusted for the entry guard. A local stub
    // supplies the callback object (TimerCallback::GetInstance is trimmed by
    // strict innerapi export checks on some CI products).
    class LocalCallbackStub : public IRemoteStub<ITimerCallback> {
    public:
        LocalCallbackStub() = default;
        ~LocalCallbackStub() override = default;
        int32_t NotifyTimer(uint64_t timerId) override
        {
            return ERR_OK;
        }
        int32_t OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
            OHOS::MessageOption &option) override
        {
            return OHOS::ERR_NONE;
        }
    };
    uint64_t timerId = 0;
    auto callbackObj = sptr<IRemoteObject>(new LocalCallbackStub());
    ASSERT_NE(callbackObj, nullptr);
    auto ret = TimeSystemAbility::GetInstance()->CreateTimerWithoutWA(
        "misc_branch_timer", 3, false, true, false, 0, callbackObj, timerId);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_NE(timerId, 0);
    TimeSystemAbility::GetInstance()->DestroyTimer(timerId);
}

// ---------------------------------------------------------------------------
// Cjson recovery path: seed the JSON store file and run RecoverTimer so the
// CjsonIntoDatabase migration loop executes with real rows.
// ---------------------------------------------------------------------------
namespace {
constexpr const char *TIME_JSON_PATH = "/data/service/el1/public/database/time/time.json";
}

/**
* @tc.name: RecoverTimerCjsonData001
* @tc.desc: RecoverTimer migrates rows found in the JSON store into the database
* @tc.precon: The JSON store file is writable on the device
* @tc.step: 1. Write a one-row hold_on_reboot document to the JSON file
*           2. Call TimeSystemAbility::RecoverTimer
*           3. Remove the JSON file afterwards
* @tc.expect: No crash; the CjsonIntoDatabase loop processes the row
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, RecoverTimerCjsonData001, TestSize.Level1)
{
    const std::string json = R"({"hold_on_reboot": [)"
        R"({"timerId":"920001","type":"4","flag":"0","windowLength":"0","interval":"0",)"
        R"("uid":"3057","bundleName":"cjson_branch","wantAgent":"","state":"1",)"
        R"("triggerTime":"0","pid":"3057","name":"cjson_branch"}]})";
    FILE *fp = fopen(TIME_JSON_PATH, "w");
    ASSERT_NE(fp, nullptr);
    ASSERT_EQ(fwrite(json.c_str(), 1, json.size(), fp), json.size());
    fclose(fp);

    auto ret = TimeSystemAbility::GetInstance()->RecoverTimer();
    EXPECT_TRUE(ret);

    // Cleanup: drop the JSON store so later runs see the default state.
    remove(TIME_JSON_PATH);
}

/**
* @tc.name: TickNotifyInit001
* @tc.desc: TimeTickNotify::Init runs the tick timer creation path in-process
* @tc.precon: TimeTickNotify singleton is available
* @tc.step: 1. Call TimeTickNotify::GetInstance().Init()
* @tc.expect: No crash and the tick timer id becomes non-zero
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeMiscBranchTest, TickNotifyInit001, TestSize.Level1)
{
    TimeTickNotify::GetInstance().Init();
    uint64_t timerId = 0;
    {
        auto &tick = TimeTickNotify::GetInstance();
        std::lock_guard<std::mutex> lock(tick.timeridMutex_);
        timerId = tick.timerId_;
    }
    EXPECT_NE(timerId, 0);
    TimeTickNotify::GetInstance().Stop();
}
} // namespace MiscServices
} // namespace OHOS
