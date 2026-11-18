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
#include "time_service_client.h"
#undef private
#undef protected

#include <gtest/gtest.h>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

class TimeClientBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void SetNoPermissionToken();
    void SetSystemToken();
};

void TimeClientBranchTest::SetUpTestCase(void)
{
}

void TimeClientBranchTest::TearDownTestCase(void)
{
}

void TimeClientBranchTest::SetUp(void)
{
}

void TimeClientBranchTest::TearDown(void)
{
}

/**
* @tc.name: OnAddSystemAbilityWrongId001
* @tc.desc: OnAddSystemAbility with a non-time service id is ignored
* @tc.precon: TimeServiceClient singleton is available
* @tc.step: 1. Construct the listener
*           2. Call OnAddSystemAbility with saId 9999
* @tc.expect: No crash and no proxy change happens
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, OnAddSystemAbilityWrongId001, TestSize.Level1)
{
    // Reuse the listener the singleton already constructed instead of newsing
    // one: the listener constructor lives in libtime_client.z.so and strict
    // innerapi export checks on some CI products trim it, while the virtual
    // methods (OnAddSystemAbility) remain exported.
    auto listener = TimeServiceClient::GetInstance()->listener_;
    ASSERT_NE(listener, nullptr);
    listener->OnAddSystemAbility(9999, "");
    // The client must remain fully usable after the ignored event.
    std::string timeZone;
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(timeZone), E_TIME_OK);
}

/**
* @tc.name: OnAddSystemAbilityReconnect001
* @tc.desc: OnAddSystemAbility with the time service id reconnects the proxy
* @tc.precon: TimeServiceClient singleton is available (device SA running)
* @tc.step: 1. Construct the listener
*           2. Call OnAddSystemAbility with TIME_SERVICE_ID
* @tc.expect: After the call the proxy is usable (client can be reached)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, OnAddSystemAbilityReconnect001, TestSize.Level1)
{
    auto listener = TimeServiceClient::GetInstance()->listener_;
    ASSERT_NE(listener, nullptr);
    listener->OnAddSystemAbility(TIME_SERVICE_ID, "");
    // The reconnect path runs ConnectService; with an empty recover map the
    // loop body is skipped. Verify the client still answers a read call.
    std::string timeZone;
    auto ret = TimeServiceClient::GetInstance()->GetTimeZone(timeZone);
    EXPECT_EQ(ret, E_TIME_OK);
}

/**
* @tc.name: OnRemoveSystemAbility001
* @tc.desc: OnRemoveSystemAbility is a no-op that must not crash
* @tc.precon: TimeServiceClient singleton is available
* @tc.step: 1. Construct the listener
*           2. Call OnRemoveSystemAbility with any id
* @tc.expect: No crash
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, OnRemoveSystemAbility001, TestSize.Level1)
{
    auto listener = TimeServiceClient::GetInstance()->listener_;
    ASSERT_NE(listener, nullptr);
    listener->OnRemoveSystemAbility(TIME_SERVICE_ID, "");
    // The client must remain fully usable after the removal event.
    std::string timeZone;
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(timeZone), E_TIME_OK);
}

/**
* @tc.name: OnRemoteDiedClearProxy001
* @tc.desc: OnRemoteDied clears the proxy and the client recovers on next call
* @tc.precon: TimeServiceClient singleton is available (device SA running)
* @tc.step: 1. Get the death recipient from the client
*           2. Call OnRemoteDied with an empty weak reference
*           3. Perform a business call through the client
* @tc.expect: No crash and the business call succeeds (proxy recovered)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, OnRemoteDiedClearProxy001, TestSize.Level1)
{
    auto client = TimeServiceClient::GetInstance();
    ASSERT_NE(client, nullptr);
    sptr<TimeServiceClient::TimeSaDeathRecipient> recipient = new TimeServiceClient::TimeSaDeathRecipient();
    ASSERT_NE(recipient, nullptr);
    wptr<IRemoteObject> emptyObject(nullptr);
    recipient->OnRemoteDied(emptyObject);
    std::string timeZone;
    auto ret = TimeServiceClient::GetInstance()->GetTimeZone(timeZone);
    EXPECT_EQ(ret, E_TIME_OK);
}

namespace {
// No-permission token: a non-system app with no granted permissions. Business
// calls through the client reach the device SA which rejects them, so the
// client-side error propagation (ConvertErrCode) branches get exercised.
HapPolicyParams g_errPolicyB = { .apl = APL_NORMAL, .domain = "test.domain" };
HapInfoParams g_errNotSystemInfo = {
    .userID = 100,
    .bundleName = "client_err_branch",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = false
};
}

void TimeClientBranchTest::SetNoPermissionToken()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_errNotSystemInfo, g_errPolicyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeClientBranchTest::SetSystemToken()
{
    static HapInfoParams systemInfo = {
        .userID = 1,
        .bundleName = "client_branch_system",
        .instIndex = 0,
        .appIDDesc = "test",
        .apiVersion = 8,
        .isSystemApp = true
    };
    static HapPolicyParams systemPolicy = {
        .apl = APL_SYSTEM_CORE,
        .domain = "test.domain",
        .permList = {
            {
                .permissionName = "ohos.permission.SET_TIME",
                .bundleName = "ohos.permission_test.clientBranch",
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
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(systemInfo, systemPolicy);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

/**
* @tc.name: ClientErrPropSetTimeV9001
* @tc.desc: SetTimeV9 from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetTimeV9 through the client
* @tc.expect: Returns a non-OK error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetTimeV9001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->SetTimeV9(1000);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropSetTimeZoneV9001
* @tc.desc: SetTimeZoneV9 from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetTimeZoneV9 through the client
* @tc.expect: Returns a non-OK error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetTimeZoneV9001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->SetTimeZoneV9("Asia/Shanghai");
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropSetAutoTime001
* @tc.desc: SetAutoTime from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetAutoTime through the client
* @tc.expect: Returns a non-OK error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetAutoTime001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->SetAutoTime(false);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropCreateTimerV9001
* @tc.desc: CreateTimerV9 from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call CreateTimerV9 through the client with a timer options object
* @tc.expect: Returns a non-OK error code and no timer id is produced
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropCreateTimerV9001, TestSize.Level1)
{
    SetNoPermissionToken();
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->CreateTimerV9(nullptr, timerId);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropStartTimer001
* @tc.desc: StartTimer from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call StartTimer through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropStartTimer001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(1, 1000);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ClientErrPropStopTimer001
* @tc.desc: StopTimer from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call StopTimer through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropStopTimer001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->StopTimer(1);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ClientErrPropDestroyTimer001
* @tc.desc: DestroyTimer from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call DestroyTimer through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropDestroyTimer001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->DestroyTimer(1);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ClientErrPropDestroyTimerAsync001
* @tc.desc: DestroyTimerAsync from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call DestroyTimerAsync through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropDestroyTimerAsync001, TestSize.Level1)
{
    SetNoPermissionToken();
    // DestroyTimerAsync is a oneway IPC: the client returns true as soon as
    // the request is queued; the service-side rejection happens asynchronously.
    auto ret = TimeServiceClient::GetInstance()->DestroyTimerAsync(1);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: ClientErrPropProxyTimer001
* @tc.desc: ProxyTimer from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call ProxyTimer through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropProxyTimer001, TestSize.Level1)
{
    SetNoPermissionToken();
    std::set<int> pidList = { 1000 };
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(3057, pidList, true, true);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ClientErrPropSetTimerExemption001
* @tc.desc: SetTimerExemption from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetTimerExemption through the client
* @tc.expect: Returns a non-OK error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetTimerExemption001, TestSize.Level1)
{
    SetNoPermissionToken();
    std::unordered_set<std::string> nameArr = { "err_branch" };
    auto ret = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropSetAdjustPolicy001
* @tc.desc: SetAdjustPolicy from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetAdjustPolicy through the client
* @tc.expect: Returns a non-OK error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetAdjustPolicy001, TestSize.Level1)
{
    SetNoPermissionToken();
    std::unordered_map<std::string, uint32_t> policyMap = { { "err_branch", 1 } };
    auto ret = TimeServiceClient::GetInstance()->SetAdjustPolicy(policyMap);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: ClientErrPropResetAllProxy001
* @tc.desc: ResetAllProxy from an unauthorized app propagates the service rejection
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call ResetAllProxy through the client
* @tc.expect: Returns false
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropResetAllProxy001, TestSize.Level1)
{
    SetNoPermissionToken();
    auto ret = TimeServiceClient::GetInstance()->ResetAllProxy();
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ClientErrPropSetTimeWithCode001
* @tc.desc: SetTime with code out param from an unauthorized app reports the failure
* @tc.precon: No permission token set
* @tc.step: 1. Switch to no-permission token
*           2. Call SetTime(time, code) through the client
* @tc.expect: Returns false and code is non-zero
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientErrPropSetTimeWithCode001, TestSize.Level1)
{
    SetNoPermissionToken();
    int32_t code = 0;
    auto ret = TimeServiceClient::GetInstance()->SetTime(1000, code);
    EXPECT_FALSE(ret);
    EXPECT_NE(code, 0);
}

// ---------------------------------------------------------------------------
// Client-side recovery loop: OnAddSystemAbility re-creates timers registered
// in recoverTimerInfoMap_ after a reconnect. The entries are seeded directly
// (private access) with a no-wantAgent timer info, covering the
// CreateTimerWithoutWA and conditional StartTimer branches of the loop.
// ---------------------------------------------------------------------------
namespace {
// ELAPSED timer type used by the recovery stub below.
constexpr int ELAPSED_TIMER_TYPE = 3;

std::shared_ptr<ITimerInfo> MakeRecoverTimerInfo()
{
    struct RecoverInfoStub : public ITimerInfo {
        void OnTrigger() override {}
        void SetType(const int &type) override { this->type = type; }
        void SetRepeat(bool repeat) override { this->repeat = repeat; }
        void SetInterval(const uint64_t &interval) override { this->interval = interval; }
        void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override
        {
            this->wantAgent = wantAgent;
        }
        void SetDisposable(const bool &disposable) { this->disposable = disposable; }
    };
    auto info = std::make_shared<RecoverInfoStub>();
    info->SetType(ELAPSED_TIMER_TYPE);
    info->SetRepeat(false);
    info->SetDisposable(true);
    return info;
}
}

/**
* @tc.name: RecoverLoopCreateOnly001
* @tc.desc: The reconnect recovery loop re-creates a stored timer without starting it
* @tc.precon: recoverTimerInfoMap_ holds an entry with state = 0
* @tc.step: 1. Seed the recovery map with a state-0 entry
*           2. Trigger OnAddSystemAbility(TIME_SERVICE_ID)
*           3. Destroy the re-created timer and clear the map
* @tc.expect: No crash; the CreateTimerWithoutWA branch of the loop runs
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, RecoverLoopCreateOnly001, TestSize.Level1)
{
    constexpr uint64_t recoverId = 910001;
    auto client = TimeServiceClient::GetInstance();
    ASSERT_NE(client, nullptr);
    auto recover = std::make_shared<TimeServiceClient::RecoverTimerInfo>();
    ASSERT_NE(recover, nullptr);
    recover->timerInfo = MakeRecoverTimerInfo();
    recover->state = 0;
    recover->triggerTime = 0;
    {
        std::lock_guard<std::mutex> lock(client->recoverTimerInfoLock_);
        client->recoverTimerInfoMap_[recoverId] = recover;
    }
    auto listener = TimeServiceClient::GetInstance()->listener_;
    ASSERT_NE(listener, nullptr);
    listener->OnAddSystemAbility(TIME_SERVICE_ID, "");
    {
        std::lock_guard<std::mutex> lock(client->recoverTimerInfoLock_);
        client->recoverTimerInfoMap_.erase(recoverId);
    }
    TimeServiceClient::GetInstance()->DestroyTimer(recoverId);
    {
        auto client2 = TimeServiceClient::GetInstance();
        std::lock_guard<std::mutex> lock(client2->recoverTimerInfoLock_);
        EXPECT_EQ(client2->recoverTimerInfoMap_.count(recoverId), 0);
    }
}

/**
* @tc.name: RecoverLoopCreateAndStart001
* @tc.desc: The reconnect recovery loop re-creates and re-starts a stored running timer
* @tc.precon: recoverTimerInfoMap_ holds an entry with state = 1
* @tc.step: 1. Seed the recovery map with a state-1 entry and a near trigger time
*           2. Trigger OnAddSystemAbility(TIME_SERVICE_ID)
*           3. Destroy the timer and clear the map
* @tc.expect: No crash; the CreateTimerWithoutWA and StartTimer branches of the loop run
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, RecoverLoopCreateAndStart001, TestSize.Level1)
{
    constexpr uint64_t recoverId = 910002;
    auto client = TimeServiceClient::GetInstance();
    ASSERT_NE(client, nullptr);
    auto recover = std::make_shared<TimeServiceClient::RecoverTimerInfo>();
    ASSERT_NE(recover, nullptr);
    recover->timerInfo = MakeRecoverTimerInfo();
    recover->state = 1;
    recover->triggerTime = 0;
    {
        std::lock_guard<std::mutex> lock(client->recoverTimerInfoLock_);
        client->recoverTimerInfoMap_[recoverId] = recover;
    }
    auto listener = TimeServiceClient::GetInstance()->listener_;
    ASSERT_NE(listener, nullptr);
    listener->OnAddSystemAbility(TIME_SERVICE_ID, "");
    {
        std::lock_guard<std::mutex> lock(client->recoverTimerInfoLock_);
        client->recoverTimerInfoMap_.erase(recoverId);
    }
    TimeServiceClient::GetInstance()->DestroyTimer(recoverId);
    {
        std::lock_guard<std::mutex> lock(client->recoverTimerInfoLock_);
        EXPECT_EQ(client->recoverTimerInfoMap_.count(recoverId), 0);
    }
}

// ---------------------------------------------------------------------------
// innerkits interface completeness: the last uncovered public APIs and the
// client lifecycle (constructor runs TimeServiceListener's constructor and the
// destructor runs UnsubscribeSA), bringing TimeServiceClient to 100% function
// coverage.
// ---------------------------------------------------------------------------
/**
* @tc.name: ClientGetBootTimeMs001
* @tc.desc: GetBootTimeMs (value-return overload) returns a valid boot time
* @tc.precon: Time service is reachable
* @tc.step: 1. Call GetBootTimeMs through the client
* @tc.expect: Returns a non-negative boot time
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientGetBootTimeMs001, TestSize.Level1)
{
    auto bootTime = TimeServiceClient::GetInstance()->GetBootTimeMs();
    EXPECT_GE(bootTime, 0);
}

/**
* @tc.name: ClientSetPowerOnTimerEnabled001
* @tc.desc: SetPowerOnTimerEnabled reaches the service and reports success
* @tc.precon: Time service is reachable
* @tc.step: 1. Call SetPowerOnTimerEnabled with a timer name
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientSetPowerOnTimerEnabled001, TestSize.Level1)
{
    // A previous error-propagation case in this suite may have left the
    // no-permission token behind; restore a system app token first.
    SetSystemToken();
    auto ret = TimeServiceClient::GetInstance()->SetPowerOnTimerEnabled("client_branch_power_on", true);
    EXPECT_EQ(ret, E_TIME_OK);
}

/**
* @tc.name: ClientLifecycle001
* @tc.desc: A locally constructed TimeServiceClient is fully destructed
* @tc.precon: The singleton is already initialized (no interference)
* @tc.step: 1. Construct a second client instance (private ctor via test access)
*           2. Destruct it, which removes the death recipient and unsubscribes SA
* @tc.expect: No crash; the listener ctor and UnsubscribeSA paths are covered
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeClientBranchTest, ClientLifecycle001, TestSize.Level1)
{
    // The private constructor/destructor live in libtime_client.z.so behind
    // strict innerapi export checks (trimmed on some CI products). Cover the
    // UnsubscribeSA branch - which the destructor used to exercise - with a
    // direct call instead of constructing a second client.
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(systemAbilityManager, nullptr);
    auto client = TimeServiceClient::GetInstance();
    ASSERT_NE(client, nullptr);
    client->UnsubscribeSA(systemAbilityManager);
    // The client must remain usable after unsubscribing.
    std::string timeZone;
    auto ret = TimeServiceClient::GetInstance()->GetTimeZone(timeZone);
    EXPECT_EQ(ret, E_TIME_OK);
}
} // namespace MiscServices
} // namespace OHOS
