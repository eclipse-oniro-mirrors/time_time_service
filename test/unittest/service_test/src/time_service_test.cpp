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

#define private public
#define protected public
#include "sntp_client.h"
#include "ntp_update_time.h"
#include "time_system_ability.h"
#include "ntp_trusted_time.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

const int RESERVED_UID = 99999;
uint64_t g_selfTokenId = 0;
const std::string NTP_CN_SERVER = "ntp.aliyun.com";
const std::string AUTOTIME_FILE_PATH = "/data/service/el1/public/time/autotime.json";
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NETWORK_TIME_STATUS_ON = "ON";

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

HapInfoParams g_systemInfoParams = { .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true };

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

HapInfoParams g_notSystemInfoParams = {
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
};

void TimeServiceTest::SetUpTestCase(void)
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
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

/**
* @tc.name: SetTime001
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime001, TestSize.Level1)
{
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
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
}

/**
* @tc.name: SetTimeZone001
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTimeZone001, TestSize.Level1)
{
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
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 5);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: CreateTimer002
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer002, TestSize.Level1)
{
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
}

/**
* @tc.name: CreateTimer003
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer003, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
}

/**
* @tc.name: CreateTimer004
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer004, TestSize.Level1)
{
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
}

/**
* @tc.name: CreateTimer005
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer005, TestSize.Level1)
{
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
}

/**
* @tc.name: CreateTimer006
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer006, TestSize.Level1)
{
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(nullptr);
    uint64_t ret = 0;
    EXPECT_EQ(timerId1, ret);
}

/**
* @tc.name: ProxyTimer001.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer001, TestSize.Level0)
{
    SetSelfTokenID(g_selfTokenId);

    int32_t uid = 99999;
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, false, true);
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
    int32_t uid = RESERVED_UID;
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
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
    int32_t uid = RESERVED_UID;
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, false, true);
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
    int32_t uid = RESERVED_UID;
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, true, false);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(uid, false, false);
    EXPECT_TRUE(ret);
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
    auto ret = ntpClient->RequestTime(NTP_CN_SERVER);
    EXPECT_FALSE(ret);

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
* @tc.name: NtpUpdateTime001.
* @tc.desc: test NtpUpdateTime.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(TimeServiceTest, NtpUpdateTime001, TestSize.Level0)
{
    auto ntpUpdateTime = std::make_shared<NtpUpdateTime>();
    ntpUpdateTime->autoTimeInfo_.lastUpdateTime = 0;

    ntpUpdateTime->autoTimeInfo_.status = NETWORK_TIME_STATUS_OFF;
    ntpUpdateTime->RefreshNetworkTimeByTimer(123);
    ntpUpdateTime->autoTimeInfo_.status = NETWORK_TIME_STATUS_ON;
    ntpUpdateTime->RefreshNetworkTimeByTimer(123);
    ntpUpdateTime->nitzUpdateTimeMilli_ = steady_clock::now().time_since_epoch().count();
    ntpUpdateTime->RefreshNetworkTimeByTimer(123);
    EXPECT_EQ(ntpUpdateTime->autoTimeInfo_.lastUpdateTime, 0);
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
} // namespace