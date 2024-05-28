/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "time_service_test.h"

#include <chrono>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sys/stat.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "timer_info_test.h"
#include "token_setproc.h"
#include "want_agent.h"
#include "timer_call_back.h"
#include "time_common.h"
#include "power_subscriber.h"

#define private public
#define protected public
#include "sntp_client.h"
#include "ntp_update_time.h"
#include "time_system_ability.h"
#include "ntp_trusted_time.h"
#include "time_tick_notify.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

const int32_t RESERVED_UID = 99999;
std::set<int> RESERVED_PIDLIST = {1111, 2222};
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NETWORK_TIME_STATUS_ON = "ON";
uint64_t g_idleTimerId = 0;

static HapPolicyParams g_policyA = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .bundleName = "ohos.permission_test.demoB",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        },
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .bundleName = "ohos.permission_test.demoB",
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

static HapInfoParams g_systemInfoParams = {
    .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

static HapInfoParams g_notSystemInfoParams = {
    .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
};

class TimeServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void AddPermission();
    void DeletePermission();
    void StartIdleTimer();
    void DestroyIdleTimer();
};

void TimeServiceTest::SetUpTestCase(void)
{
}

void TimeServiceTest::TearDownTestCase(void)
{
}

void TimeServiceTest::SetUp(void)
{
}

void TimeServiceTest::TearDown(void)
{
}

void TimeServiceTest::AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTest::DeletePermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_notSystemInfoParams, g_policyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTest::StartIdleTimer()
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_IDLE);
    timerInfo->SetRepeat(false);
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, g_idleTimerId);
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(g_idleTimerId, time + 5000);
}

void TimeServiceTest::DestroyIdleTimer()
{
    TimeServiceClient::GetInstance()->DestroyTimerV9(g_idleTimerId);
}

/**
* @tc.name: ProxyTimer001.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer001, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, false, true);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: ProxyTimer002.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer002, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ResetAllProxy();
    EXPECT_TRUE(ret);
}

/**
* @tc.name: ProxyTimer003.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer003, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, false, true);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ProxyTimer004.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer004, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, true, false);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, false, false);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: PidProxyTimer001.
* @tc.desc: proxy timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, PidProxyTimer001, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, false, true);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: PidProxyTimer002.
* @tc.desc: proxy timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, PidProxyTimer002, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ResetAllProxy();
    EXPECT_TRUE(ret);
}

/**
* @tc.name: PidProxyTimer003.
* @tc.desc: proxy timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, PidProxyTimer003, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, false, true);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: PidProxyTimer004.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, PidProxyTimer004, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, true, false);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_PIDLIST, false, false);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: AdjustTimer001.
* @tc.desc: adjust timer.
* @tc.type: FUNC
* @tc.require: AR20240306656104
*/
HWTEST_F(TimeServiceTest, AdjustTimer001, TestSize.Level0)
{
    auto errCode = TimeServiceClient::GetInstance()->AdjustTimer(true, 5);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->AdjustTimer(false, 0);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: AdjustTimer002.
* @tc.desc: exemption timer.
* @tc.type: FUNC
* @tc.require: AR20240306656104
*/
HWTEST_F(TimeServiceTest, AdjustTimer002, TestSize.Level0)
{
    std::unordered_set<std::string> nameArr{"timer"};
    auto errCode = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: IdleTimer001.
* @tc.desc: test create idle timer for app.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, IdleTimer001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_IDLE);
    timerInfo->SetRepeat(false);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer002
* @tc.desc: test public app start timer when device is sleeping and device sleep quit greater than timer callback.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, IdleTimer002, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    StartIdleTimer();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + 2000);
    sleep(2);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    sleep(1);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer003
* @tc.desc: test public app start timer when device is sleeping and device sleep quit less than timer callback.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, IdleTimer003, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    StartIdleTimer();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + 6000);
    sleep(6);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    sleep(6);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer004
* @tc.desc: test public app start timer when device is working, device sleep immediately
*           and timer callback greater than idle quit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, IdleTimer004, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time + 6000));
    StartIdleTimer();
    sleep(6);
    DestroyIdleTimer();
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: SetTime001
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime001, TestSize.Level1)
{
    AddPermission();
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    DeletePermission();
}

/**
* @tc.name: SetTime002
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(-1);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime003
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime003, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(LLONG_MAX);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime004
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime004, TestSize.Level1)
{
    AddPermission();
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t code;
    bool result = TimeServiceClient::GetInstance()->SetTime(time, code);
    EXPECT_TRUE(result);
    EXPECT_EQ(code, 0);
    DeletePermission();
}

/**
* @tc.name: SetTimeZone001
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTimeZone001, TestSize.Level1)
{
    AddPermission();
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneNicosia("Asia/Nicosia");
    bool result = TimeServiceClient::GetInstance()->SetTimeZone(timeZoneNicosia);
    EXPECT_TRUE(result);
    auto getTimeZoneNicosia = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone(getCurrentTimeZone);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: SetTimeZone002
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTimeZone002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTimeZone("123");
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTimeZone003
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTimeZone003, TestSize.Level1)
{
    AddPermission();
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneShanghai("Asia/Shanghai");
    int32_t code;
    bool result = TimeServiceClient::GetInstance()->SetTimeZone(timeZoneShanghai, code);
    EXPECT_TRUE(result);
    EXPECT_EQ(code, 0);
    auto getTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(getTimeZone, timeZoneShanghai);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone(getCurrentTimeZone);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: GetWallTimeMs001
* @tc.desc: get wall time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetWallTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetWallTimeNs001
* @tc.desc: get wall time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetWallTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetBootTimeNs001
* @tc.desc: get boot time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetBootTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetMonotonicTimeMs001
* @tc.desc: get monotonic time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetMonotonicTimeNs001
* @tc.desc: get monotonic time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetThreadTimeMs001
* @tc.desc: get thread time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_TRUE(time1 != -1);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: get thread time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_TRUE(time1 != -1);
}

/**
* @tc.name: CreateTimer001
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer001, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 5);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer002
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer002, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId1);
    EXPECT_TRUE(timerId1 > 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId1, 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId1);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer003
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer003, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
    DeletePermission();
}

/**
* @tc.name: CreateTimer004
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer004, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
    auto BootTimeNano = system_clock::now().time_since_epoch().count();
    auto BootTimeMilli = BootTimeNano / NANO_TO_MILESECOND;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId1, BootTimeMilli + 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(g_data1 == 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId1);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer005
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer005, TestSize.Level1)
{
    AddPermission();
    g_data1 = 1;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);

    struct timeval timeOfDay {
    };
    gettimeofday(&timeOfDay, NULL);
    int64_t currentTime = (timeOfDay.tv_sec + 100) * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);

    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId1, static_cast<uint64_t>(currentTime));
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(g_data1 == 1);

    ret = TimeServiceClient::GetInstance()->StopTimer(timerId1);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer006
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer006, TestSize.Level1)
{
    AddPermission();
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(nullptr);
    uint64_t ret = 0;
    EXPECT_EQ(timerId1, ret);
    DeletePermission();
}

/**
* @tc.name: SntpClient001.
* @tc.desc: test SntpClient.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, SntpClient001, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();

    auto buffer = std::string("31234114451");
    auto millisecond = ntpClient->GetNtpTimestamp64(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);
    millisecond = 0;
    millisecond = ntpClient->GetNtpField32(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);

    auto timeStamp = ntpClient->ConvertNtpToStamp(0);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(100);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(2147483648);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(31234114451);
    EXPECT_EQ(timeStamp, 0);
    uint64_t time = 999999999911;
    timeStamp = ntpClient->ConvertNtpToStamp(time << 32);
    EXPECT_GT(timeStamp, 0);
}

/**
* @tc.name: NtpTrustedTime001.
* @tc.desc: test NtpTrustedTime.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, NtpTrustedTime001, TestSize.Level0)
{
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = nullptr;
    int64_t errCode = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_EQ(errCode, -1);
    errCode = ntpTrustedTime->GetCacheAge();
    EXPECT_EQ(errCode, INT_MAX);

    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(0, 0, 0);
    int64_t time = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_GT(time, 0);
    int64_t cacheAge = ntpTrustedTime->GetCacheAge();
    EXPECT_GT(cacheAge, 0);
}

/**
* @tc.name: PowerSubscriber001
* @tc.desc: test power subscriber data is invalid.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, PowerSubscriber001, TestSize.Level0)
{
    auto timerId = TimeTickNotify::GetInstance().timerId_;
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED;
    EventFwk::Want want;
    want.SetAction(commonEvent);
    int32_t code = 100;
    std::string data(commonEvent);
    EventFwk::CommonEventData eventData(want, code, data);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    auto subscriber = std::make_shared<PowerSubscriber>(CommonEventSubscribeInfo(matchingSkills));
    subscriber->OnReceiveEvent(eventData);
    EXPECT_EQ(timerId, TimeTickNotify::GetInstance().timerId_);
}

/**
* @tc.name: PowerSubscriber002
* @tc.desc: test power subscriber data is valid.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, PowerSubscriber002, TestSize.Level0)
{
    auto timerId = TimeTickNotify::GetInstance().timerId_;
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON;
    EventFwk::Want want;
    want.SetAction(commonEvent);
    int32_t code = RESERVED_UID;
    std::string data(commonEvent);
    EventFwk::CommonEventData eventData(want, code, data);
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    auto subscriber = std::make_shared<PowerSubscriber>(CommonEventSubscribeInfo(matchingSkills));
    subscriber->OnReceiveEvent(eventData);
    EXPECT_NE(timerId, TimeTickNotify::GetInstance().timerId_);
}
} // namespace