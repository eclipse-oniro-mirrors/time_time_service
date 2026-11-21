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
#include "time_permission.h"
#include "time_service_client.h"
#undef private
#undef protected

#include <ctime>

#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr uint64_t TIMER_ID_BRANCH = 987654;
// Full permission policy: system app with SET_TIME / SET_TIME_ZONE granted.
HapPolicyParams g_branchPolicyA = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .bundleName = "ohos.permission_test.branch",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        },
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .bundleName = "ohos.permission_test.branch",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

// Plain app policy: no permissions at all.
HapPolicyParams g_branchPolicyB = { .apl = APL_NORMAL, .domain = "test.domain" };

// System app info: isSystemApp = true.
HapInfoParams g_branchSystemInfo = {
    .userID = 1,
    .bundleName = "timer_branch",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

// Non-system app info: isSystemApp = false (hits E_TIME_NOT_SYSTEM_APP paths).
HapInfoParams g_branchNotSystemInfo = {
    .userID = 100,
    .bundleName = "timer_branch",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = false
};
} // namespace

// Minimal ITimerInfo stub, defined locally to avoid the header-only
// TimerInfoTest which cannot be included by two translation units of the same
// target (duplicate symbol at link time).
class BranchTimerInfo : public ITimerInfo {
public:
    BranchTimerInfo() = default;
    ~BranchTimerInfo() override = default;

    void OnTrigger() override
    {
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

class TimeServicePermissionBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void SetSystemAppToken();
    void SetNotSystemAppToken();
};

void TimeServicePermissionBranchTest::SetUpTestCase(void)
{
}

void TimeServicePermissionBranchTest::TearDownTestCase(void)
{
}

void TimeServicePermissionBranchTest::SetUp(void)
{
}

void TimeServicePermissionBranchTest::TearDown(void)
{
    // Always restore the default (system app, full permission) token and detach
    // any mock authorization client, so later suites in this binary are not
    // affected by permission states left behind by a branch case.
    TimePermission::ResetAuthorizationClient();
    SetSystemAppToken();
}

void TimeServicePermissionBranchTest::SetSystemAppToken()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_branchSystemInfo, g_branchPolicyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServicePermissionBranchTest::SetNotSystemAppToken()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_branchNotSystemInfo, g_branchPolicyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

/**
* @tc.name: SetTimeNotSystemApp001
* @tc.desc: SetTime with API_VERSION_9 from a non-system app token
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::SetTime with API_VERSION_9
* @tc.expect: SetTime returns E_TIME_NOT_SYSTEM_APP without touching system time
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, SetTimeNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    auto result = TimeSystemAbility::GetInstance()->SetTime(time, APIVersion::API_VERSION_9);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}


/**
* @tc.name: CreateTimerNotSystemApp001
* @tc.desc: CreateTimer (string-arg overload) from a non-system app token is rejected
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call the string-arg CreateTimer overload
* @tc.expect: CreateTimer returns E_TIME_NOT_SYSTEM_APP and no timer id is produced
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, CreateTimerNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    uint64_t timerId = 0;
    auto result = TimeSystemAbility::GetInstance()->CreateTimerWithoutWA(
        "branch_timer", 3, false, false, false, 0, nullptr, timerId);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimerObjNullptr001
* @tc.desc: CreateTimer (ITimerInfo overload) with a null remote callback object
* @tc.precon: Current token has full permissions (system app)
* @tc.step: 1. Switch to system app token with permissions
*           2. Call CreateTimer with a valid timer options object but null obj
* @tc.expect: CreateTimer returns E_TIME_NULLPTR and no timer id is produced
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, CreateTimerObjNullptr001, TestSize.Level1)
{
    SetSystemAppToken();
    auto timerInfo = std::make_shared<BranchTimerInfo>();
    ASSERT_NE(timerInfo, nullptr);
    uint64_t timerId = 0;
    sptr<IRemoteObject> callback = nullptr;
    auto result = TimeSystemAbility::GetInstance()->CreateTimer(timerInfo, callback, timerId);
    EXPECT_EQ(result, E_TIME_NULLPTR);
    EXPECT_EQ(timerId, 0);
}


/**
* @tc.name: SetTimeZoneNotSystemApp001
* @tc.desc: SetTimeZone with API_VERSION_9 from a non-system app token
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::SetTimeZone with API_VERSION_9
* @tc.expect: SetTimeZone returns E_TIME_NOT_SYSTEM_APP
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, SetTimeZoneNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->SetTimeZone("Asia/Shanghai", APIVersion::API_VERSION_9);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}


/**
* @tc.name: StartTimerNotSystemApp001
* @tc.desc: StartTimer from a non-system app token is rejected at the entry guard
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::StartTimer with any timer id
* @tc.expect: StartTimer returns E_TIME_NOT_SYSTEM_APP
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, StartTimerNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->StartTimer(1, 0);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: StopTimerNotSystemApp001
* @tc.desc: StopTimer from a non-system app token is rejected at the entry guard
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::StopTimer with any timer id
* @tc.expect: StopTimer returns E_TIME_NOT_SYSTEM_APP
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, StopTimerNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->StopTimer(1);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: DestroyTimerNotSystemApp001
* @tc.desc: DestroyTimer from a non-system app token is rejected at the entry guard
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::DestroyTimer with any timer id
* @tc.expect: DestroyTimer returns E_TIME_NOT_SYSTEM_APP
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, DestroyTimerNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->DestroyTimer(1);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: StartTimerNotFound001
* @tc.desc: StartTimer with a non-existent timer id fails in the manager layer
* @tc.precon: Current token is a system app with permissions
* @tc.step: 1. Switch to system app token
*           2. Call StartTimer with a timer id that was never created
* @tc.expect: StartTimer returns E_TIME_DEAL_FAILED
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, StartTimerNotFound001, TestSize.Level1)
{
    SetSystemAppToken();
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t triggerTime = static_cast<uint64_t>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000) + 60000;
    auto result = TimeSystemAbility::GetInstance()->StartTimer(TIMER_ID_BRANCH, triggerTime);
    EXPECT_EQ(result, E_TIME_DEAL_FAILED);
}

/**
* @tc.name: StopTimerNotFound001
* @tc.desc: StopTimer with a non-existent timer id fails in the manager layer
* @tc.precon: Current token is a system app with permissions
* @tc.step: 1. Switch to system app token
*           2. Call StopTimer with a timer id that was never created
* @tc.expect: StopTimer returns E_TIME_DEAL_FAILED
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, StopTimerNotFound001, TestSize.Level1)
{
    SetSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->StopTimer(TIMER_ID_BRANCH);
    EXPECT_EQ(result, E_TIME_DEAL_FAILED);
}

/**
* @tc.name: SetPowerOnTimerEnabledNotSystemApp001
* @tc.desc: SetPowerOnTimerEnabled from a non-system app token is rejected
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call TimeSystemAbility::SetPowerOnTimerEnabled
* @tc.expect: SetPowerOnTimerEnabled returns E_TIME_NOT_SYSTEM_APP
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, SetPowerOnTimerEnabledNotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    auto result = TimeSystemAbility::GetInstance()->SetPowerOnTimerEnabled("branch_power_on", true);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
}

namespace {
// Minimal in-TU callback stub: iface_cast<ITimerCallback> on the SA create
// path requires a real IRemoteStub, so the CheckTimerPara cases below need a
// valid callback object (the permission-reject cases do not reach it).
class BranchCallbackStub : public IRemoteStub<ITimerCallback> {
public:
    BranchCallbackStub() = default;
    ~BranchCallbackStub() override = default;
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

sptr<IRemoteObject> MakeBranchCallback()
{
    sptr<BranchCallbackStub> callback = new (std::nothrow) BranchCallbackStub();
    return callback;
}
} // namespace

/**
* @tc.name: CreateTimerWithWANotSystemApp001
* @tc.desc: The want-agent CreateTimer overload from a non-system app token is rejected
* @tc.precon: Current token is a plain app without system app flag
* @tc.step: 1. Switch to non-system-app token
*           2. Call the want-agent CreateTimer overload
* @tc.expect: CreateTimer returns E_TIME_NOT_SYSTEM_APP and no timer id is produced
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, CreateTimerWithWANotSystemApp001, TestSize.Level1)
{
    SetNotSystemAppToken();
    OHOS::AbilityRuntime::WantAgent::WantAgent wantAgent;
    uint64_t timerId = 0;
    auto result = TimeSystemAbility::GetInstance()->CreateTimer(
        "branch_timer_wa", 3, false, false, false, 0, wantAgent, MakeBranchCallback(), timerId);
    EXPECT_EQ(result, E_TIME_NOT_SYSTEM_APP);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimerAutoRestoreRealtimeReject001
* @tc.desc: autoRestore on an elapsed-realtime timer is rejected by parameter checking
* @tc.precon: Current token is a system app (default)
* @tc.step: 1. Call CreateTimerWithoutWA with autoRestore=true and the
*              ELAPSED_REALTIME type
* @tc.expect: Returns E_TIME_AUTO_RESTORE_ERROR without creating a timer
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, CreateTimerAutoRestoreRealtimeReject001, TestSize.Level1)
{
    SetSystemAppToken();
    // Go through the ITimerInfo overload: the string-arg overloads wrap the
    // parameter-check result as E_TIME_DEAL_FAILED, while this one returns the
    // precise code, which is what the assertion below pins down.
    auto info = std::make_shared<BranchTimerInfo>();
    ASSERT_NE(info, nullptr);
    info->SetType(1); // ELAPSED_REALTIME
    info->autoRestore = true;
    uint64_t timerId = 0;
    auto result = TimeSystemAbility::GetInstance()->CreateTimer(info, MakeBranchCallback(), timerId);
    EXPECT_EQ(result, E_TIME_AUTO_RESTORE_ERROR);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimerNameTooLongReject001
* @tc.desc: A timer name longer than STR_MAX_LENGTH is rejected by parameter checking
* @tc.precon: Current token is a system app (default)
* @tc.step: 1. Build a name of STR_MAX_LENGTH + 1 characters
*           2. Call CreateTimerWithoutWA with it
* @tc.expect: Returns E_TIME_PARAMETERS_INVALID without creating a timer
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeServicePermissionBranchTest, CreateTimerNameTooLongReject001, TestSize.Level1)
{
    SetSystemAppToken();
    // Same reason as the auto-restore case: the ITimerInfo overload returns
    // the precise parameter-check code.
    auto info = std::make_shared<BranchTimerInfo>();
    ASSERT_NE(info, nullptr);
    info->SetType(0); // RTC
    info->name = std::string(65, 'a'); // STR_MAX_LENGTH is 64.
    uint64_t timerId = 0;
    auto result = TimeSystemAbility::GetInstance()->CreateTimer(info, MakeBranchCallback(), timerId);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
    EXPECT_EQ(timerId, 0);
}
} // namespace MiscServices
} // namespace OHOS
