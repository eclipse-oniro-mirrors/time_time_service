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
#include "event_manager.h"
#include "ntp_update_time.h"
#include "cjson_helper.h"

#define private public
#define protected public
#include "sntp_client.h"
#include "ntp_update_time.h"
#include "time_system_ability.h"
#include "ntp_trusted_time.h"
#include "time_tick_notify.h"
#include "timer_proxy.h"
#include "time_service_test.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

std::set<int> RESERVED_PIDLIST = {1111, 2222};
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NETWORK_TIME_STATUS_ON = "ON";
const std::string AUTO_TIME_STATUS_ON = "ON";
const uint64_t TIMER_ID = 88888;
constexpr int64_t MINUTE_TO_MILLISECOND = 60000;
constexpr char BYTE_SNTP_MESSAGE = 0xD8;
constexpr int64_t MAX_TIME_DRIFT_IN_ONE_DAY = 2000;
constexpr int64_t MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS = 100;
constexpr int64_t ONE_DAY = 86400000;
constexpr int64_t ONE_HOUR = 3600000;
constexpr int64_t TWO_SECOND = 2000;
constexpr int64_t ONE_SECOND = 1000;

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

class TimeServiceTimeTest : public testing::Test {
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

void TimeServiceTimeTest::SetUpTestCase(void)
{
}

void TimeServiceTimeTest::TearDownTestCase(void)
{
}

void TimeServiceTimeTest::SetUp(void)
{
}

void TimeServiceTimeTest::TearDown(void)
{
}

void TimeServiceTimeTest::AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTimeTest::DeletePermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_notSystemInfoParams, g_policyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TestNtpThread(const char *name)
{
    {
        std::lock_guard<std::mutex> autoLock(NtpUpdateTime::requestMutex_);
    }
    NtpUpdateTime::SetSystemTime();
}

/**
* @tc.name: SetTime001
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTime001, TestSize.Level1)
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
* @tc.desc: Verify set system time with negative value will return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTime002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(-1);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime003
* @tc.desc: Verify set system time with LLONG_MAX will return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTime003, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(LLONG_MAX);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime004
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTime004, TestSize.Level1)
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
    auto res = TimeSystemAbility::GetInstance()->SetTime(0, 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimeInner001
* @tc.desc: set system time by ability.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTimeInner001, TestSize.Level1)
{
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    auto result = TimeSystemAbility::GetInstance()->SetTimeInner(time);
    EXPECT_EQ(result, E_TIME_OK);
}


/**
* @tc.name: SetTimeZone001
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone001, TestSize.Level1)
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
* @tc.desc: Verify set system time zone with invalid timezone will return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTimeZone("123");
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTimeZone003
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone003, TestSize.Level1)
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
    auto res = TimeSystemAbility::GetInstance()->SetTimeZone("", 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimeZoneInner001
* @tc.desc: set system time zone by ability.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZoneInner001, TestSize.Level1)
{
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneNicosia("Asia/Shanghai");
    bool result = TimeSystemAbility::GetInstance()->SetTimeZoneInner(timeZoneNicosia);
    EXPECT_EQ(result, E_TIME_OK);
    auto getTimeZoneNicosia = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    auto ret = TimeSystemAbility::GetInstance()->SetTimeZoneInner(getCurrentTimeZone);
    EXPECT_EQ(ret, E_TIME_OK);
}

/**
* @tc.name: GetWallTimeMs001
* @tc.desc: get wall time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, GetWallTimeMs001, TestSize.Level1)
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
HWTEST_F(TimeServiceTimeTest, GetWallTimeNs001, TestSize.Level1)
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
HWTEST_F(TimeServiceTimeTest, GetBootTimeNs001, TestSize.Level1)
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
HWTEST_F(TimeServiceTimeTest, GetMonotonicTimeMs001, TestSize.Level1)
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
HWTEST_F(TimeServiceTimeTest, GetMonotonicTimeNs001, TestSize.Level1)
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
HWTEST_F(TimeServiceTimeTest, GetThreadTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_NE(time1, -1);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: get thread time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, GetThreadTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_NE(time1, -1);
}

/**
* @tc.name: SntpClient001
* @tc.desc: test GetNtpTimestamp64 will return timestamp.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient001, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto buffer = std::string("31234114451");
    auto millisecond = ntpClient->GetNtpTimestamp64(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);
}

/**
* @tc.name: SntpClient002
* @tc.desc: test GetNtpField32 will return time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient002, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto buffer = std::string("31234114451");
    auto millisecond = ntpClient->GetNtpField32(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);
}

/**
* @tc.name: SntpClient003
* @tc.desc: test ConvertNtpToStamp with invalid value will return 0 timestamp.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient003, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto timeStamp = ntpClient->ConvertNtpToStamp(0);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(100);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(2147483648);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(31234114451);
    EXPECT_EQ(timeStamp, 0);
}

/**
* @tc.name: SntpClient004
* @tc.desc: test ConvertNtpToStamp with valid value will return true timestamp.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient004, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    uint64_t time = 999999999911;
    auto timeStamp = ntpClient->ConvertNtpToStamp(time << 32);
    EXPECT_EQ(timeStamp, 1358598439000);
}

/**
* @tc.name: SntpClient005
* @tc.desc: Verify RequestTime with null string will return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient005, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto res = ntpClient -> RequestTime("");
    EXPECT_FALSE(res);
}

/**
* @tc.name: SntpClient006
* @tc.desc: test SetClockOffset of SntpClient.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient006, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    ntpClient -> SetClockOffset(1);
    EXPECT_EQ(ntpClient -> m_clockOffset, 1);
}

/**
* @tc.name: SntpClient007
* @tc.desc: test ConvertUnixToNtp of SntpClient.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient007, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    OHOS::MiscServices::SNTPClient::ntp_timestamp ntp{.second = 0, .fraction = 0};
    struct timeval unix;
    gettimeofday(&unix, nullptr);
    ntpClient -> ConvertUnixToNtp(&ntp, &unix);
    EXPECT_NE(ntp.second, 0);
    EXPECT_NE(ntp.fraction, 0);
}

/**
* @tc.name: SntpClient008
* @tc.desc: test CreateMessage of SntpClient.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient008, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char sendBuf[48] = { 0 };
    ntpClient -> CreateMessage(sendBuf);
    EXPECT_EQ(sendBuf[0], '\x1B');
}

/**
* @tc.name: SntpClient009
* @tc.desc: test ReceivedMessage will return true when received valid message.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient009, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char buf[48] = {0};
    buf[32] = BYTE_SNTP_MESSAGE;
    buf[40] = BYTE_SNTP_MESSAGE;
    auto res = ntpClient -> ReceivedMessage(buf);
    EXPECT_TRUE(res);
}

/**
* @tc.name: SntpClient010
* @tc.desc: test ReceivedMessage will return false when received invalid message.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient010, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char buf[48] = {0};
    auto res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
    buf[32] = BYTE_SNTP_MESSAGE;
    buf[40] = 0;
    res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
    buf[32] = 0;
    buf[40] = BYTE_SNTP_MESSAGE;
    res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
}

/**
* @tc.name: SntpClient011
* @tc.desc: test GetReferenceId of SntpClient.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient011, TestSize.Level0)
{
    char buf[5] = {'1', '2', '3', '4', '5'};
    int array[5] = {0};
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    ntpClient -> GetReferenceId(0, buf, array);
    EXPECT_EQ(array[0], '1');
}

/**
* @tc.name: SntpClient012
* @tc.desc: test Get of SntpClient.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SntpClient012, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    std::shared_ptr<SNTPClient::SNTPMessage> sntpMessage = std::make_shared<SNTPClient::SNTPMessage>();
    sntpMessage -> clear();
    ntpClient -> mNtpTime = 1;
    ntpClient -> mNtpTimeReference = 2;
    ntpClient -> mRoundTripTime = 3;
    EXPECT_EQ(ntpClient -> getNtpTime(), 1);
    EXPECT_EQ(ntpClient -> getNtpTimeReference(), 2);
    EXPECT_EQ(ntpClient -> getRoundTripTime(), 3);
}

/**
* @tc.name: NtpTrustedTime001
* @tc.desc: test NtpTrustedTime with invalid value.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime001, TestSize.Level0)
{
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = nullptr;
    int64_t errCode = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_EQ(errCode, -1);
    errCode = ntpTrustedTime->GetCacheAge();
    EXPECT_EQ(errCode, INT_MAX);
}

/**
* @tc.name: NtpTrustedTime002
* @tc.desc: test NtpTrustedTime with valid value.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime002, TestSize.Level0)
{
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(1, 1, 0);
    int64_t time = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_GT(time, 0);
    int64_t cacheAge = ntpTrustedTime->GetCacheAge();
    EXPECT_GT(cacheAge, 0);
}

/**
* @tc.name: NtpTrustedTime003
* @tc.desc: test NtpTrustedTime clear.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime003, TestSize.Level0)
{
    auto TimeResult = std::make_shared<OHOS::MiscServices::NtpTrustedTime::TimeResult>();
    TimeResult->Clear();
    EXPECT_EQ(TimeResult->mTimeMillis, 0);
    EXPECT_EQ(TimeResult->mElapsedRealtimeMillis, 0);
    EXPECT_EQ(TimeResult->mCertaintyMillis, 0);
}

/**
* @tc.name: NtpTrustedTime004
* @tc.desc: test GetTimeMillis.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime004, TestSize.Level0)
{
    auto TimeResult = std::make_shared<OHOS::MiscServices::NtpTrustedTime::TimeResult>();
    TimeResult->Clear();
    auto res = TimeResult->GetTimeMillis();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name: NtpTrustedTime005
* @tc.desc: test func IsTimeResultTrusted.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime005, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    // test mTimeResult is nullptr
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = nullptr;
    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    bool ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 1);

    // test mTimeResult is unavailable due to time out
    auto wallTime1 = wallTime - 2 * ONE_DAY;
    auto bootTime1 = bootTime - 2 * ONE_DAY;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime1, bootTime1, 0);
    ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 2);

    // test new result Within the margin of error
    auto wallTime2 = wallTime - ONE_HOUR - MAX_TIME_DRIFT_IN_ONE_DAY;
    auto bootTime2 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0);
    ret = false;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);

    auto wallTime3 = wallTime - ONE_HOUR + MAX_TIME_DRIFT_IN_ONE_DAY;
    auto bootTime3 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0);
    ret = false;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime006
* @tc.desc: test func IsTimeResultTrusted.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime006, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    // test mTimeResult is nullptr
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    
    // test new result out of the margin of error
    auto wallTime1 = wallTime - ONE_HOUR - MAX_TIME_DRIFT_IN_ONE_DAY - TWO_SECOND;
    auto bootTime1 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime1, bootTime1, 0);
    auto ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime1);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime1);
    EXPECT_EQ(ret, false);

    auto wallTime2 = wallTime - ONE_HOUR + MAX_TIME_DRIFT_IN_ONE_DAY + TWO_SECOND;
    auto bootTime2 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0);
    ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime2);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime2);
}

/**
* @tc.name: NtpTrustedTime007
* @tc.desc: test func FindBestTimeResult with 3 same candidates, return true.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime007, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // three time is similar, vote for 3 candidate
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    auto wallTime2 = wallTime + ONE_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0);
    auto wallTime3 = wallTime + TWO_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS / 2;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0);
    bool ret = true;
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime008
* @tc.desc: test func FindBestTimeResult with 2 same candidates, return true.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime008, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // two time is similar, vote for 3 candidate
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    auto wallTime2 = wallTime + TWO_SECOND;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0);
    auto wallTime3 = wallTime + TWO_SECOND;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    bool ret = false;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime009
* @tc.desc: test func FindBestTimeResult with no same candidates, return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime009, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // test 3 timeResult got different time
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    auto wallTime2 = wallTime + TWO_SECOND;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0);
    auto wallTime3 = wallTime + TWO_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS * 2;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    bool ret = true;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime010
* @tc.desc: test func FindBestTimeResult with 0 or 1 candidates.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime010, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    bool ret = true;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);

    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult);
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: TimeTick001
* @tc.desc: Check RefreshNextTriggerTime.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, TimeTick001, TestSize.Level0)
{
    AddPermission();
    int64_t time = 0;
    TimeUtils::GetWallTimeMs(time);
    time = (time / MINUTE_TO_MILLISECOND) * MINUTE_TO_MILLISECOND;
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    auto pair = TimeTickNotify::GetInstance().RefreshNextTriggerTime();
    EXPECT_EQ(pair.first, time + MINUTE_TO_MILLISECOND);
    EXPECT_TRUE(pair.second);
    DeletePermission();
}

/**
* @tc.name: SetSystemTime001
* @tc.desc: get ntp time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, SetSystemTime001, TestSize.Level1)
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
* @tc.name: NtpTime001
* @tc.desc: test SplitNtpAddrs return max size.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTime001, TestSize.Level0)
{
    const std::string ntpStr = "aaa,bbb,ccc,ddd,eee,fff";
    auto res = NtpUpdateTime::GetInstance().SplitNtpAddrs(ntpStr);
    EXPECT_EQ(res.size(), 5);
}

/**
* @tc.name: NtpTime002
* @tc.desc: test RefreshNetworkTimeByTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, NtpTime002, TestSize.Level0)
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

/**
* @tc.name: GetNtpTimeMsWithNoPermission001
* @tc.desc: test GetNtpTimeMs with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, GetNtpTimeMsWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    int64_t time = 0;
    auto res = TimeSystemAbility::GetInstance()->GetNtpTimeMs(time);
    EXPECT_EQ(res, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: GetRealTimeMsWithNoPermission001
* @tc.desc: test GetRealTimeMs with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimeTest, GetRealTimeMsWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    int64_t time = 0;
    auto res = TimeSystemAbility::GetInstance()->GetRealTimeMs(time);
    EXPECT_EQ(res, E_TIME_NOT_SYSTEM_APP);
}
} // namespace