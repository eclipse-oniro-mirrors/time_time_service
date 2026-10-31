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
#include <chrono>

#include <gtest/gtest.h>

#include "time_common.h"
#include "time_service_client.h"
#include "timer_info.h"
#include "want_agent.h"
#include "parameters.h"

#define private public
#define protected public
#include "time_system_ability.h"
#include "timer_manager.h"
#include "timer_database.h"
#include "cjson_helper.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;

#ifdef SET_AUTO_REBOOT_ENABLE
const uint64_t TIMER_ID = 88888;
const int UID = 999998;
static const int POWER_ON_ALARM = 6;
#endif

class PowerOnTimerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PowerOnTimerTest::SetUpTestCase(void)
{
}

void PowerOnTimerTest::TearDownTestCase(void)
{
}

void PowerOnTimerTest::SetUp(void)
{
}

void PowerOnTimerTest::TearDown(void)
{
#ifdef SET_AUTO_REBOOT_ENABLE
    // Clear the shared disabled registry so a later test (including original
    // TimeServiceTimerTest cases in the same process) is not affected by the
    // timer ids this fixture disabled.
    TimerManager::GetInstance()->disabledPowerOnTimerIds_.clear();
#endif
}

#ifdef SET_AUTO_REBOOT_ENABLE
std::shared_ptr<TimerEntry> MakePowerOnEntry(uint64_t timerId, const std::string &name, int uid, bool autoRestore)
{
    auto entry = std::make_shared<TimerEntry>();
    entry->name = name;
    entry->id = timerId;
    entry->type = ITimerManager::TimerType::RTC;
    entry->windowLength = -1;
    entry->interval = 0;
    entry->flag = 0;
    entry->autoRestore = autoRestore;
    entry->uid = uid;
    entry->pid = 0;
    entry->bundleName = "testBundleName";
    return entry;
}

std::shared_ptr<TimerInfo> MakePowerOnTimerInfo(uint64_t timerId, const std::string &name, int uid, bool autoRestore,
    int64_t triggerTime)
{
    auto timePoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(10000);
    return std::make_shared<TimerInfo>(name, timerId, ITimerManager::TimerType::RTC,
        std::chrono::milliseconds(triggerTime), timePoint, std::chrono::milliseconds(triggerTime), timePoint,
        std::chrono::milliseconds(0), nullptr, nullptr, 0, autoRestore, uid, 0, "testBundleName");
}

void SetupPowerOnTimer(uint64_t timerId, const std::string &name, int uid, bool autoRestore)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnApps_ = {"testBundleName", name};
    tm->timerEntryMap_[timerId] = MakePowerOnEntry(timerId, name, uid, autoRestore);
    tm->timerNameMap_[uid][name] = timerId;
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName001
 * @tc.desc: Test disable a power-on timer by name puts its id into the disabled registry and reschedules
 * @tc.expect: disabledPowerOnTimerIds_ contains the timer id; ret is E_TIME_OK
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    tm->lastSetTime_[POWER_ON_ALARM] = 0;
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(TIMER_ID, "testTimerName", UID, true,
        currentTime + 10000));
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 1);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName002
 * @tc.desc: Test disabling a non-power-on timer does not change the disabled registry
 * @tc.expect: disabledPowerOnTimerIds_ stays empty
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName002, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    // autoRestore=false and bundle not in NEED_RECOVER_ON_REBOOT. Non-CALLBACK
    // form: CheckNeedRecoverOnReboot fails -> not a power-on timer. CALLBACK
    // form: classification only checks type RTC/RTC_WAKEUP + whitelist match,
    // so the timer is power-on regardless of autoRestore.
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, false);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    #ifdef CALLBACK_AUTOBOOT_ENABLE
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 1);
    #else
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.size(), 0);
    #endif
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName003
 * @tc.desc: Test disabling with no matching timer name is idempotent with no side effect
 * @tc.expect: disabledPowerOnTimerIds_ empty and no reschedule (lastSetTime_ unchanged)
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName003, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->lastSetTime_[POWER_ON_ALARM] = 0;
    auto ret = tm->SetPowerOnTimerEnabledByName("noSuchTimer", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.size(), 0);
    EXPECT_EQ(tm->lastSetTime_[POWER_ON_ALARM], 0);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName004
 * @tc.desc: Test enable=true restores a disabled timer (removes id from disabled registry)
 * @tc.expect: disabledPowerOnTimerIds_ no longer contains the timer id
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName004, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", true);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 0);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName005
 * @tc.desc: Test enable=true on an already-enabled timer is idempotent
 * @tc.expect: disabledPowerOnTimerIds_ stays empty
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName005, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", true);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.size(), 0);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName006
 * @tc.desc: Test same name across multiple uids is disabled by a single call
 * @tc.expect: both timer ids are in the disabled registry
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName006, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    SetupPowerOnTimer(TIMER_ID, "sameName", UID, true);
    SetupPowerOnTimer(TIMER_ID + 1, "sameName", UID + 1, true);
    auto ret = tm->SetPowerOnTimerEnabledByName("sameName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 1);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID + 1), 1);
}

/**
 * @tc.name: IsPowerOnTimerDisabled001
 * @tc.desc: Test IsPowerOnTimerDisabled returns correct membership of disabled registry
 * @tc.expect: false when not disabled, true after insert
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, IsPowerOnTimerDisabled001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->disabledPowerOnTimerIds_.clear();
    EXPECT_FALSE(tm->IsPowerOnTimerDisabled(TIMER_ID));
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID);
    EXPECT_TRUE(tm->IsPowerOnTimerDisabled(TIMER_ID));
}

/**
 * @tc.name: GetNextPowerOnTriggerTimeLocked001
 * @tc.desc: Test GetNextPowerOnTriggerTimeLocked skips disabled timers and picks the next enabled one
 * @tc.expect: returns the second earliest timer when the earliest is disabled
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, GetNextPowerOnTriggerTimeLocked001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    // List must be trigger-time ascending (as maintained by ReschedulePowerOnTimerLocked).
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(3, "t3", UID, true, currentTime + 10000));
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(2, "t2", UID, true, currentTime + 20000));
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(1, "t1", UID, true, currentTime + 30000));
    tm->disabledPowerOnTimerIds_.insert(3);
    std::chrono::milliseconds setTimePoint(0);
    bool found = tm->GetNextPowerOnTriggerTimeLocked(currentTime, setTimePoint);
    EXPECT_TRUE(found);
    EXPECT_EQ(setTimePoint.count(), currentTime + 20000);
}

/**
 * @tc.name: GetNextPowerOnTriggerTimeLocked002
 * @tc.desc: Test GetNextPowerOnTriggerTimeLocked returns false when all timers are disabled or list is empty
 * @tc.expect: returns false and leaves setTimePoint unchanged
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, GetNextPowerOnTriggerTimeLocked002, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(1, "t1", UID, true, currentTime + 10000));
    tm->disabledPowerOnTimerIds_.insert(1);
    std::chrono::milliseconds setTimePoint(0);
    bool found = tm->GetNextPowerOnTriggerTimeLocked(currentTime, setTimePoint);
    EXPECT_FALSE(found);
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    found = tm->GetNextPowerOnTriggerTimeLocked(currentTime, setTimePoint);
    EXPECT_FALSE(found);
}

/**
 * @tc.name: GetNextPowerOnTriggerTimeLocked003
 * @tc.desc: Test GetNextPowerOnTriggerTimeLocked cleans expired timers from the list
 * @tc.expect: expired timers are erased and no trigger time is returned
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, GetNextPowerOnTriggerTimeLocked003, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(1, "t1", UID, true, currentTime - 10000));
    std::chrono::milliseconds setTimePoint(0);
    bool found = tm->GetNextPowerOnTriggerTimeLocked(currentTime, setTimePoint);
    EXPECT_FALSE(found);
    EXPECT_EQ(tm->powerOnTriggerTimerList_.size(), 0);
}

/**
 * @tc.name: ReschedulePowerOnTimerLockedDisabled001
 * @tc.desc: Test ReschedulePowerOnTimerLocked sets never-trigger when all timers are disabled
 * @tc.expect: lastSetTime_[POWER_ON_ALARM] is set to currentTime + ten years
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, ReschedulePowerOnTimerLockedDisabled001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->lastSetTime_[POWER_ON_ALARM] = 0;
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(TIMER_ID, "testTimerName", UID, true,
        currentTime + 10000));
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID);
    #ifdef CALLBACK_AUTOBOOT_ENABLE
    tm->ReschedulePowerOnTimerLocked(false);
    #else
    tm->ReschedulePowerOnTimerLocked();
    #endif
    EXPECT_GT(tm->lastSetTime_[POWER_ON_ALARM], currentTime);
}

/**
 * @tc.name: ReschedulePowerOnTimerLockedDisabled002
 * @tc.desc: Test ReschedulePowerOnTimerLocked is idempotent when the RTC value is unchanged
 * @tc.expect: lastSetTime_[POWER_ON_ALARM] stays the same and no rewrite happens
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, ReschedulePowerOnTimerLockedDisabled002, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->powerOnTriggerTimerList_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    tm->powerOnTriggerTimerList_.push_back(MakePowerOnTimerInfo(TIMER_ID, "testTimerName", UID, true,
        currentTime + 10000));
    tm->lastSetTime_[POWER_ON_ALARM] = currentTime + 10000;
    #ifdef CALLBACK_AUTOBOOT_ENABLE
    tm->ReschedulePowerOnTimerLocked(false);
    #else
    tm->ReschedulePowerOnTimerLocked();
    #endif
    EXPECT_EQ(tm->lastSetTime_[POWER_ON_ALARM], currentTime + 10000);
}

/**
 * @tc.name: StopTimerInnerLocked001
 * @tc.desc: Test destroying a disabled power-on timer erases its id from the disabled registry
 * @tc.expect: disabledPowerOnTimerIds_ no longer contains the destroyed timer id
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, StopTimerInnerLocked001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID);
    bool needRecover = false;
    tm->StopTimerInnerLocked(true, TIMER_ID, needRecover);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 0);
}

/**
 * @tc.name: CheckTimerPara001
 * @tc.desc: Test CheckTimerPara rejects autoRestore with ELAPSED timers and NOT_STORE database type
 * @tc.expect: E_TIME_AUTO_RESTORE_ERROR for ELAPSED/NOT_STORE, E_TIME_OK for RTC+STORE
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, CheckTimerPara001, TestSize.Level0)
{
    TimerPara paras {};
    paras.autoRestore = true;
    paras.timerType = ITimerManager::TimerType::ELAPSED_REALTIME;
    auto ret = TimeSystemAbility::GetInstance()->CheckTimerPara(DatabaseType::STORE, paras);
    EXPECT_EQ(ret, E_TIME_AUTO_RESTORE_ERROR);
    paras.timerType = ITimerManager::TimerType::RTC;
    ret = TimeSystemAbility::GetInstance()->CheckTimerPara(DatabaseType::STORE, paras);
    EXPECT_EQ(ret, E_TIME_OK);
    ret = TimeSystemAbility::GetInstance()->CheckTimerPara(DatabaseType::NOT_STORE, paras);
    EXPECT_EQ(ret, E_TIME_AUTO_RESTORE_ERROR);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName007
 * @tc.desc: SetPowerOnTimerEnabledByName matches a timer name across multiple uids
 * @tc.precon: TimerManager is available
 * @tc.step: 1. Register the same power-on timer name for two uids
 *           2. Disable by name
 *           3. Verify both uids' timers are disabled
 * @tc.expect: Both timers with the matching name are disabled
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName007, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    SetupPowerOnTimer(TIMER_ID + 1, "testTimerName", UID + 1, true);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_TRUE(tm->IsPowerOnTimerDisabled(TIMER_ID));
    EXPECT_TRUE(tm->IsPowerOnTimerDisabled(TIMER_ID + 1));
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName008
 * @tc.desc: SetPowerOnTimerEnabledByName with an unknown name is a silent no-op
 * @tc.precon: TimerManager is available
 * @tc.step: 1. Disable a name that matches no registered timer
 *           2. Verify operation returns E_TIME_OK and no timer is affected
 * @tc.expect: E_TIME_OK with no registry change for an unmatched name
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName008, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->disabledPowerOnTimerIds_.clear();
    auto ret = tm->SetPowerOnTimerEnabledByName("noSuchTimer", false);
    EXPECT_EQ(ret, E_TIME_OK);
    // No timer was disabled.
    EXPECT_FALSE(tm->IsPowerOnTimerDisabled(TIMER_ID));
}

/**
 * @tc.name: SetPowerOnTimerEnabledByName009
 * @tc.desc: SetPowerOnTimerEnabledByName skips a name whose timer entry is gone
 * @tc.precon: TimerManager is available
 * @tc.step: 1. Register a timer name then remove the timer entry
 *           2. Disable by name
 *           3. Verify no disabled registry change
 * @tc.expect: E_TIME_OK with no disabled entry when the timer entry is missing
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByName009, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->disabledPowerOnTimerIds_.clear();
    SetupPowerOnTimer(TIMER_ID, "testTimerName", UID, true);
    // Timer name is registered, but the timer entry is removed (entryMap_ miss).
    tm->timerEntryMap_.erase(TIMER_ID);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_FALSE(tm->IsPowerOnTimerDisabled(TIMER_ID));
}

/**
 * @tc.name: SetAutoRebootSkipDisabled001
 * @tc.desc: SetAutoReboot skips a disabled power-on timer (continue branch)
 * @tc.precon: TimeDatabase is available, SET_AUTO_REBOOT_ENABLE is on
 * @tc.step: 1. Register a power-on timer and disable it
 *           2. Insert a HOLD_ON_REBOOT row for the disabled timer with a future trigger
 *           3. Call SetAutoReboot
 *           4. Verify it completes without arming the disabled timer
 * @tc.expect: SetAutoReboot continues past the disabled timer without crashing
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetAutoRebootSkipDisabled001, TestSize.Level0)
{
    uint64_t timerId = TIMER_ID;
    auto tm = TimerManager::GetInstance();
    // Register + disable the power-on timer so IsPowerOnTimerDisabled(timerId) is true.
    SetupPowerOnTimer(timerId, "testTimerName", UID, true);
    auto ret = tm->SetPowerOnTimerEnabledByName("testTimerName", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_TRUE(tm->IsPowerOnTimerDisabled(timerId));

    // DB holds a future-trigger row for the disabled timer.
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", static_cast<int64_t>(timerId));
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", UID);
    insertValues1.PutString("bundleName", "testBundleName");
    insertValues1.PutString("wantAgent", "");
    insertValues1.PutInt("state", 1);
    // A distant-future trigger so the row is not skipped by the triggerTime check.
    insertValues1.PutLong("triggerTime", static_cast<int64_t>(currentTime + 24 * 60 * 60 * 1000));
    insertValues1.PutString("name", "testTimerName");
    auto insertRes = TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);
    EXPECT_EQ(insertRes, true);

    // The disabled row is skipped by the continue branch; no crash, no arm.
    TimeSystemAbility::GetInstance()->SetAutoReboot();

    // Cleanup the inserted row.
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByNameEnableAll001
 * @tc.desc: Empty name with enable=true clears the whole disabled registry (enable all)
 * @tc.expect: disabledPowerOnTimerIds_ is empty after the call
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByNameEnableAll001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    SetupPowerOnTimer(TIMER_ID, "t1", UID, true);
    SetupPowerOnTimer(TIMER_ID + 1, "t2", UID + 1, true);
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID);
    tm->disabledPowerOnTimerIds_.insert(TIMER_ID + 1);
    auto ret = tm->SetPowerOnTimerEnabledByName("", true);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.size(), 0);
}

/**
 * @tc.name: SetPowerOnTimerEnabledByNameDisableAll001
 * @tc.desc: Empty name with enable=false marks every power-on timer disabled (disable all)
 * @tc.expect: all power-on timer ids are in the disabled registry
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(PowerOnTimerTest, SetPowerOnTimerEnabledByNameDisableAll001, TestSize.Level0)
{
    auto tm = TimerManager::GetInstance();
    tm->timerEntryMap_.clear();
    tm->timerNameMap_.clear();
    tm->disabledPowerOnTimerIds_.clear();
    tm->powerOnTriggerTimerList_.clear();
    SetupPowerOnTimer(TIMER_ID, "t1", UID, true);
    SetupPowerOnTimer(TIMER_ID + 1, "t2", UID + 1, true);
    auto ret = tm->SetPowerOnTimerEnabledByName("", false);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID), 1);
    EXPECT_EQ(tm->disabledPowerOnTimerIds_.count(TIMER_ID + 1), 1);
}

#endif
} // namespace
