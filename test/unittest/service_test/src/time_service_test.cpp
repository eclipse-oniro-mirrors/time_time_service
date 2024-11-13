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
#include "ntp_update_time.h"

#define private public
#define protected public
#include "sntp_client.h"
#include "ntp_update_time.h"
#include "time_system_ability.h"
#include "ntp_trusted_time.h"
#include "time_tick_notify.h"
#include "timer_database.h"
#include "timer_proxy.h"
#include "timer_notify_callback.h"

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
const std::string AUTO_TIME_STATUS_ON = "ON";
uint64_t g_idleTimerId = 0;
const uint64_t TIMER_ID = 88888;
const int UID = 999998;
const int PID = 999999;
constexpr int ONE_HUNDRED = 100;
constexpr int FIVE_HUNDRED = 500;
constexpr uint64_t MICRO_TO_MILLISECOND = 1000;

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
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
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
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
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
    .userID = 100,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = false
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
    // 5000 means timer triggers after 5s
    TimeServiceClient::GetInstance()->StartTimerV9(g_idleTimerId, time + 5000);
}

void TimeServiceTest::DestroyIdleTimer()
{
    TimeServiceClient::GetInstance()->DestroyTimerV9(g_idleTimerId);
}

void TestNtpThread(const char *name)
{
    {
        std::lock_guard<std::mutex> autoLock(NtpUpdateTime::requestMutex_);
    }
    NtpUpdateTime::SetSystemTime();
}

/**
 * @brief Wait for timer trigger
 * @param data the global variable that callback function changes
 * @param interval the time need to wait
 */
void WaitForAlarm(std::atomic<int> * data, int interval)
{
    int i = 0;
    if (interval > 0) {
        usleep(interval);
    }
    while (*data == 0 && i < ONE_HUNDRED) {
        ++i;
        usleep(ONE_HUNDRED*MICRO_TO_MILLISECOND);
    }
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
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->AdjustTimer(false, 0);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
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
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + FIVE_HUNDRED);
    usleep(FIVE_HUNDRED*MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + FIVE_HUNDRED);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time + FIVE_HUNDRED));
    StartIdleTimer();
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, ONE_HUNDRED * MICRO_TO_MILLISECOND);
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
    ASSERT_GT(time, 0);
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
    ASSERT_GT(time, 0);
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
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetWallTimeNs001
* @tc.desc: get wall time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetWallTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetBootTimeNs001
* @tc.desc: get boot time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetBootTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetMonotonicTimeMs001
* @tc.desc: get monotonic time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetMonotonicTimeNs001
* @tc.desc: get monotonic time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetThreadTimeMs001
* @tc.desc: get thread time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_NE(time1, -1);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: get thread time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_NE(time1, -1);
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
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_GT(timerId, 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
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
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
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
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    auto BootTimeNano = system_clock::now().time_since_epoch().count();
    auto BootTimeMilli = BootTimeNano / NANO_TO_MILESECOND;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, BootTimeMilli + 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
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
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);

    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, static_cast<uint64_t>(currentTime));
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 1);

    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
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
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(nullptr);
    uint64_t ret = 0;
    EXPECT_EQ(timerId, ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer007
* @tc.desc: Create system timer with TIMER_TYPE_EXACT, then start timer with uint64_t::max.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer007, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer008
* @tc.desc: Create system timer with TIMER_TYPE_REALTIME and TIMER_TYPE_EXACT, then start timer with uint64_t::max.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer008, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME | timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer009
* @tc.desc: Create system timer start with one day later, then setTime to one day later.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer009, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    // Set the time to one day later
    int64_t time = (currentTime.tv_sec + 86400) * 1000 + currentTime.tv_usec / 1000;
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    ASSERT_GT(time, 0);

    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, time);
    EXPECT_TRUE(ret);

    ret = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(ret);

    // wait for the second trigger success
    while (g_data1 < 2) {
        usleep(100000);
    }
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
 * @tc.name: CreateTimer010
 * @tc.desc: Create system timer.
 * @tc.type: FUNC
 */
HWTEST_F(TimeServiceTest, CreateTimer010, TestSize.Level1) {
    AddPermission();
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 5);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimerAsync(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
 * @tc.name: CreateTimer011
 * @tc.desc: Create system timer.
 * @tc.type: FUNC
 */
HWTEST_F(TimeServiceTest, CreateTimer011, TestSize.Level1) {
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME |
                       timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimerAsync(timerId);
    EXPECT_TRUE(ret);
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

    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(1, 1, 0);
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

/**
* @tc.name: SetSystemTime001
* @tc.desc: get ntp time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetSystemTime001, TestSize.Level1)
{
    NtpUpdateTime::GetInstance().Init();
    std::string tmp = NtpUpdateTime::autoTimeInfo_.status;
    NtpUpdateTime::autoTimeInfo_.status = AUTO_TIME_STATUS_ON;

    std::thread thread1(TestNtpThread, "thread1");
    std::thread thread2(TestNtpThread, "thread2");
    std::thread thread3(TestNtpThread, "thread3");
    std::thread thread4(TestNtpThread, "thread4");
    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    NtpUpdateTime::autoTimeInfo_.status = tmp;
}

/**
* @tc.name: Batch001.
* @tc.desc: test Batch.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, Batch001, TestSize.Level0)
{
    Batch batch;
    EXPECT_EQ(batch.GetStart(), std::chrono::steady_clock::time_point::min());
    EXPECT_EQ(batch.GetEnd(), std::chrono::steady_clock::time_point::max());
    EXPECT_EQ(batch.GetFlags(), 0);
}

/**
* @tc.name: TimerManager001.
* @tc.desc: test ReCreateTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager001, TestSize.Level0)
{
    auto timerId1 = TIMER_ID;
    auto timerId2 = TIMER_ID + 1;
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{timerId1, 0, 0, 0, 0, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(timerId1, entry);
    TimerManager::GetInstance()->ReCreateTimer(timerId2, nullptr);
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->entryMapMutex_);

    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(timerId1);
    EXPECT_NE(it, map.end());
    if (it != map.end()) {
        map.erase(it);
    }
    it = map.find(timerId2);
    EXPECT_NE(it, map.end());
    if (it != map.end()) {
        map.erase(it);
    }
}

/**
* @tc.name: TimerManager002.
* @tc.desc: test SetHandler with interval = milliseconds(10) < second(1).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager002, TestSize.Level0)
{
    uint64_t max = std::numeric_limits<uint64_t>::max();
    TimerManager::GetInstance()->SetHandler(TIMER_ID,
                                            0,
                                            max,
                                            10,
                                            0,
                                            1,
                                            nullptr,
                                            nullptr,
                                            0,
                                            0,
                                            "bundleName");
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->entryMapMutex_);
    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(TIMER_ID);
    EXPECT_NE(it, map.end());
    if (it != map.end()) {
        map.erase(it);
    }
}

/**
* @tc.name: TimerManager003.
* @tc.desc: test Set() with type > ALARM_TYPE_COUNT.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager003, TestSize.Level0)
{
    auto when = std::chrono::nanoseconds::zero();
    auto bootTime = std::chrono::steady_clock::now();
    auto res = TimerManager::GetInstance()->handler_->Set(6, when, bootTime);
    EXPECT_EQ(res, -1);
}

/**
* @tc.name: TimerManager004.
* @tc.desc: test StartTimer with UidProxy and PidProxy.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager004, TestSize.Level0)
{
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{TIMER_ID, 0, 0, 0, 0, nullptr, nullptr, UID, PID, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
        TimerProxy::GetInstance().proxyUids_.insert(std::make_pair(UID, timePointMap));
    }
    auto res = TimerManager::GetInstance()->StartTimer(TIMER_ID, 0);
    EXPECT_EQ(res, E_TIME_OK);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        auto map = TimerProxy::GetInstance().proxyUids_;
        auto it = map.find(UID);
        if (it != map.end()) {
            map.erase(it);
        }
    }
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyPidMutex_);
        auto map = TimerProxy::GetInstance().proxyPids_;
        std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> timePointMap {};
        map.insert(std::make_pair(UID, timePointMap));
    }
    res = TimerManager::GetInstance()->StartTimer(TIMER_ID, 0);
    EXPECT_EQ(res, E_TIME_OK);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyPidMutex_);
        auto map = TimerProxy::GetInstance().proxyPids_;
        auto it = map.find(PID);
        if (it != map.end()) {
            map.erase(it);
        }
    }

    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
}

/**
* @tc.name: TimerManager005.
* @tc.desc: test NotifyWantAgent.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager005, TestSize.Level0)
{
    TimerManager::GetInstance()->NotifyWantAgentRetry(nullptr);
    
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>(TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, 0, 0, "");
    auto res = TimerManager::GetInstance()->NotifyWantAgent(timerInfo);
    EXPECT_FALSE(res);
    
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("timerId", TIMER_ID);
    insertValues.PutInt("type", 0);
    insertValues.PutInt("flag", 0);
    insertValues.PutLong("windowLength", 0);
    insertValues.PutLong("interval", 0);
    insertValues.PutInt("uid", 0);
    insertValues.PutString("bundleName", "");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    insertValues.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues.PutInt("state", 0);
    insertValues.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues);

    res = TimerManager::GetInstance()->NotifyWantAgent(timerInfo);
    EXPECT_FALSE(res);

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(HOLD_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(TIMER_ID));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
}

/**
* @tc.name: TimerManager006.
* @tc.desc: test AdjustTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager006, TestSize.Level0)
{
    uint32_t interval;
    bool isAdjust;
    // Set 1000 as interval, because interval can not be 0;
    uint32_t intervalSet = 1000;
    {
        std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
        interval = TimerManager::GetInstance()->adjustInterval_;
        TimerManager::GetInstance()->adjustInterval_ = intervalSet;
        isAdjust = TimerManager::GetInstance()->adjustPolicy_;
    }

    auto res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet);
    EXPECT_FALSE(res);
    res = TimerManager::GetInstance()->AdjustTimer(!isAdjust, intervalSet);
    EXPECT_TRUE(res);
    res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet + 1);
    EXPECT_TRUE(res);
    res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet);
    EXPECT_TRUE(res);

    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
    TimerManager::GetInstance()->adjustInterval_ = interval;
    TimerManager::GetInstance()->adjustPolicy_ = isAdjust;
}

/**
* @tc.name: TimerManager007.
* @tc.desc: test AdjustDeliveryTimeBasedOnDeviceIdle.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager007, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>(TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, 0, 0, "");
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
    auto alarm = TimerManager::GetInstance()->mPendingIdleUntil_;
    TimerManager::GetInstance()->mPendingIdleUntil_ = timerInfo1;
    auto res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo1);
    EXPECT_FALSE(res);

    TimerManager::GetInstance()->mPendingIdleUntil_ = nullptr;
    TimerManager::GetInstance()->delayedTimers_[TIMER_ID] = std::chrono::steady_clock::now();
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo1);
    EXPECT_TRUE(res);
    auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(
            (timePoint + std::chrono::hours(1)).time_since_epoch());
    auto timerInfo2 = std::make_shared<TimerInfo>(TIMER_ID, 1, duration1, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, 0, 0, "");
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo2);
    EXPECT_TRUE(res);
    auto timerInfo3 = std::make_shared<TimerInfo>(TIMER_ID, 2, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, 0, 0, "");
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo3);
    EXPECT_TRUE(res);

    TimerManager::GetInstance()->mPendingIdleUntil_ = alarm;
}

/**
* @tc.name: TimerManager008.
* @tc.desc: test ShowTimerEntryById TIMER_ID not in timerEntryMap_.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager008, TestSize.Level0)
{
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);

    auto res = TimerManager::GetInstance()->ShowTimerEntryById(0, TIMER_ID);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimerManager009.
* @tc.desc: test ShowTimerTriggerById TIMER_ID in alarmBatches_.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager009, TestSize.Level0)
{
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{TIMER_ID, 0, 0, 0, 0, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    uint64_t triggerTime = std::numeric_limits<uint64_t>::max();
    TimerManager::GetInstance()->StartTimer(TIMER_ID, triggerTime);
    auto res = TimerManager::GetInstance()->ShowTimerTriggerById(0, TIMER_ID);
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    EXPECT_TRUE(res);
}

/**
* @tc.name: TimerManager010.
* @tc.desc: test HandleRSSDeath.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager010, TestSize.Level0)
{
    std::shared_ptr<TimerInfo> alarm;
    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        alarm = TimerManager::GetInstance()->mPendingIdleUntil_;
        TimerManager::GetInstance()->mPendingIdleUntil_ = nullptr;
    }
    TimerManager::GetInstance()->HandleRSSDeath();

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>(TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, 0, 0, "");
    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        TimerManager::GetInstance()->mPendingIdleUntil_ = timerInfo;
    }
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{TIMER_ID, 0, 0, 0, 0, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    TimerManager::GetInstance()->HandleRSSDeath();
    auto res = TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    EXPECT_EQ(res, E_TIME_DEAL_FAILED);

    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        TimerManager::GetInstance()->mPendingIdleUntil_ = alarm;
    }
}

/**
* @tc.name: TimerManager011.
* @tc.desc: test TimerNotifyCallback GetInstance.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager011, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    auto res = TimerNotifyCallback::GetInstance(timerManager);
    EXPECT_NE(res, nullptr);
    res = TimerNotifyCallback::GetInstance(timerManager);
    EXPECT_NE(res, nullptr);
}

/**
* @tc.name: TimerManager012.
* @tc.desc: test OnPackageRemoved.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerManager012, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    {
        std::lock_guard<std::mutex> lock(timerManager->entryMapMutex_);
        timerManager->timerEntryMap_.clear();
    }

    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{TIMER_ID, 0, 0, 0, 0, nullptr, nullptr, UID, 0, "bundleName"});
    timerManager->ReCreateTimer(TIMER_ID, entry);
    timerManager->OnPackageRemoved(UID);

    {
        std::lock_guard<std::mutex> lock(timerManager->entryMapMutex_);
        auto map = timerManager->timerEntryMap_;
        auto it = map.find(TIMER_ID);
        EXPECT_EQ(it, map.end());
        if (it != map.end()) {
            map.erase(it);
        }
    }
}

/**
* @tc.name: SystemAbility001.
* @tc.desc: test OnStop.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SystemAbility001, TestSize.Level0)
{
    TimeSystemAbility::GetInstance()->OnStop();
    EXPECT_EQ(TimeSystemAbility::GetInstance()->state_, ServiceRunningState::STATE_NOT_START);
    TimeSystemAbility::GetInstance()->OnStop();
    EXPECT_EQ(TimeSystemAbility::GetInstance()->state_, ServiceRunningState::STATE_NOT_START);
}

/**
* @tc.name: SystemAbility002.
* @tc.desc: test RecoverTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SystemAbility002, TestSize.Level0)
{
    uint64_t timerId1 = TIMER_ID;
    uint64_t timerId2 = TIMER_ID + 1;

    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(timerId1);
    if (it != map.end()) {
        map.erase(it);
    }
    it = map.find(timerId2);
    if (it != map.end()) {
        map.erase(it);
    }

    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", timerId1);
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", 0);
    insertValues1.PutString("bundleName", "");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    insertValues1.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues1.PutInt("state", 0);
    insertValues1.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);

    OHOS::NativeRdb::ValuesBucket insertValues2;
    insertValues2.PutLong("timerId", timerId2);
    insertValues2.PutInt("type", 0);
    insertValues2.PutInt("flag", 0);
    insertValues2.PutLong("windowLength", 0);
    insertValues2.PutLong("interval", 0);
    insertValues2.PutInt("uid", 0);
    insertValues2.PutString("bundleName", "");
    wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    insertValues2.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues2.PutInt("state", 0);
    insertValues2.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(DROP_ON_REBOOT, insertValues2);

    TimeSystemAbility::GetInstance()->RecoverTimer();

    it = map.find(timerId1);
    EXPECT_EQ(it, map.end());
    it = map.find(timerId2);
    EXPECT_EQ(it, map.end());

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId1));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete2(DROP_ON_REBOOT);
    rdbPredicatesDelete2.EqualTo("timerId", static_cast<int64_t>(timerId2));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete2);
}

/**
* @tc.name: SystemAbility003.
* @tc.desc: test SetAutoReboot.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SystemAbility003, TestSize.Level0)
{
    uint64_t timerId1 = TIMER_ID;
    uint64_t timerId2 = TIMER_ID + 1;

    TimeSystemAbility::GetInstance()->SetAutoReboot();
    
    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", timerId1);
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", 0);
    insertValues1.PutString("bundleName", "anything");
    insertValues1.PutString("wantAgent", "");
    insertValues1.PutInt("state", 1);
    insertValues1.PutLong("triggerTime", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);
    EXPECT_EQ(res, true);

    OHOS::NativeRdb::ValuesBucket insertValues2;
    insertValues2.PutLong("timerId", timerId2);
    insertValues2.PutInt("type", 0);
    insertValues2.PutInt("flag", 0);
    insertValues2.PutLong("windowLength", 0);
    insertValues2.PutLong("interval", 0);
    insertValues2.PutInt("uid", 0);
    insertValues2.PutString("bundleName", NEED_RECOVER_ON_REBOOT[0]);
    insertValues2.PutString("wantAgent", "");
    insertValues2.PutInt("state", 1);
    insertValues2.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    res = TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues2);
    EXPECT_EQ(res, true);

    TimeSystemAbility::GetInstance()->SetAutoReboot();

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId1));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete2(HOLD_ON_REBOOT);
    rdbPredicatesDelete2.EqualTo("timerId", static_cast<int64_t>(timerId2));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete2);
}

/**
* @tc.name: SystemAbility004.
* @tc.desc: test SetRealTime.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SystemAbility004, TestSize.Level0)
{
    auto res = TimeSystemAbility::GetInstance()->SetRealTime(-1);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimeDatabase001.
* @tc.desc: test TimeDatabase Insert.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimeDatabase001, TestSize.Level0)
{
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("something", 0);
    auto res = TimeDatabase::GetInstance().Insert(DROP_ON_REBOOT, insertValues);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimeDatabase002.
* @tc.desc: test TimeDatabase Update.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimeDatabase002, TestSize.Level0)
{
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt("something", 1);
    OHOS::NativeRdb::RdbPredicates rdbPredicates(DROP_ON_REBOOT);
    rdbPredicates.EqualTo("something", 0)->And()->EqualTo("something", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Update(values, rdbPredicates);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimeDatabase003.
* @tc.desc: test TimeDatabase Delete.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimeDatabase003, TestSize.Level0)
{
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(DROP_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("something", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimerInfo001.
* @tc.desc: test UpdateWhenElapsedFromNow.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerInfo001, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo(0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
                                          nullptr, 0, 0, 0, "");
    auto res = timerInfo.UpdateWhenElapsedFromNow(timePoint, duration);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimerInfo002.
* @tc.desc: test AdjustTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, TimerInfo002, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds(0);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo(0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
                                          nullptr, 0, 0, 0, "");
    auto res = timerInfo.AdjustTimer(timePoint, 1);
    EXPECT_TRUE(res);
}

/**
* @tc.name: NtpTime001.
* @tc.desc: test SplitNtpAddrs return max size.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, NtpTime001, TestSize.Level0)
{
    const std::string ntpStr = "aaa,bbb,ccc,ddd,eee,fff";
    auto res = NtpUpdateTime::GetInstance().SplitNtpAddrs(ntpStr);
    EXPECT_EQ(res.size(), 5);
}

/**
* @tc.name: NtpTime002.
* @tc.desc: test RefreshNetworkTimeByTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, NtpTime002, TestSize.Level0)
{
    auto status = NtpUpdateTime::GetInstance().autoTimeInfo_.status;

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = NETWORK_TIME_STATUS_OFF;
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = NETWORK_TIME_STATUS_ON;
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().nitzUpdateTimeMilli_ = 0;
    auto res = NtpUpdateTime::GetInstance().IsValidNITZTime();
    EXPECT_FALSE(res);

    NtpUpdateTime::GetInstance().UpdateNITZSetTime();
    res = NtpUpdateTime::GetInstance().IsValidNITZTime();
    EXPECT_TRUE(res);
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = status;
}
} // namespace