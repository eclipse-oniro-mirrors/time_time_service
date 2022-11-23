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
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <fstream>
#include "ipc_skeleton.h"
#include "json/json.h"
#include "timer_info_test.h"
#include "time_service_test.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;

const int RESERVED_UID = 99999;

const std::string AUTOTIME_FILE_PATH = "/data/service/el1/public/time/autotime.json";
const std::string NETWORK_TIME_STATUS_ON = "ON";
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NTP_CN_SERVER = "ntp.aliyun.com";
const int64_t INVALID_TIMES = -1;

class TimeServiceTest : public testing::Test
{
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
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

struct AutoTimeInfo {
    std::string ntpServer;
    std::string status;
    int64_t lastUpdateTime;
};

bool GetAutoTimeInfoFromFile(AutoTimeInfo &info)
{
    Json::Value jsonValue;
    std::ifstream ifs;
    ifs.open(AUTOTIME_FILE_PATH);
    Json::CharReaderBuilder builder;
    builder["collectComments"] = true;
    JSONCPP_STRING errs;
    if (!parseFromStream(builder, ifs, &jsonValue, &errs)) {
        ifs.close();
        return false;
    }
    info.status = jsonValue["status"].asString();
    info.ntpServer = jsonValue["ntpServer"].asString();
    info.lastUpdateTime = jsonValue["lastUpdateTime"].asInt64();
    ifs.close();
    return true;
}

/**
* @tc.name: NetworkTimeStatusOn
* @tc.desc: network time status on.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, NetworkTimeStatusOn, TestSize.Level1)
{
    TimeServiceClient::GetInstance()->NetworkTimeStatusOn();

    AutoTimeInfo info;
    bool result = GetAutoTimeInfoFromFile(info);
    EXPECT_EQ(true, result);
    EXPECT_EQ(NETWORK_TIME_STATUS_ON, info.status);
}

/**
* @tc.name: NetworkTimeStatusOff
* @tc.desc: network time status off.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, NetworkTimeStatusOff, TestSize.Level1)
{
    TimeServiceClient::GetInstance()->NetworkTimeStatusOff();

    AutoTimeInfo info;
    bool result = GetAutoTimeInfoFromFile(info);
    EXPECT_EQ(true, result);
    EXPECT_EQ(INVALID_TIMES, info.lastUpdateTime);
    EXPECT_EQ(NTP_CN_SERVER, info.ntpServer);
    EXPECT_EQ(NETWORK_TIME_STATUS_OFF, info.status);
}

/**
* @tc.name: SetTime001
* @tc.desc: get system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTime001, TestSize.Level0)
{
    struct timeval getTime {};
    gettimeofday(&getTime, NULL);
    int64_t time = getTime.tv_sec * 1000;
    if (time < 0) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Time now invalid : %{public}" PRId64 "", time);
        time = 1627307312000;
    }
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
}

/**
* @tc.name: SetTimeZone001
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, SetTimeZone001, TestSize.Level0)
{
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    std::string timeZoneShanghai("Asia/Shanghai");
    auto getTimeZoneShanghai = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneShanghai, getTimeZoneShanghai);

    std::string timeZoneNicosia("Asia/Nicosia");
    bool result = TimeServiceClient::GetInstance()->SetTimeZone(timeZoneNicosia);
    EXPECT_TRUE(result);
    auto getTimeZoneNicosia = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);

    bool ret = TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai");
    EXPECT_TRUE(ret);
}

/**
* @tc.name: GetWallTimeMs
* @tc.desc: get wall time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetWallTimeMs, TestSize.Level0)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetWallTimeNs
* @tc.desc: get wall time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetWallTimeNs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetBootTimeNs
* @tc.desc: get boot time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetBootTimeNs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetMonotonicTimeMs
* @tc.desc: get monotonic time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeMs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetMonotonicTimeNs
* @tc.desc: get monotonic time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetMonotonicTimeNs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetThreadTimeMs
* @tc.desc: get thread time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeMs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: GetThreadTimeNs
* @tc.desc: get thread time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, GetThreadTimeNs, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_TRUE(time1 != -1);
    auto time2 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_TRUE(time2 >= time1);
}

/**
* @tc.name: CreateTimer03
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer003, TestSize.Level0)
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
* @tc.name: CreateTimer04
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer004, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId1, 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId1);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: CreateTimer05
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer005, TestSize.Level0)
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
* @tc.name: CreateTimer06.
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTest, CreateTimer006, TestSize.Level0)
{
    g_data1 = 1;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);

    struct timeval getTime {};
    gettimeofday(&getTime, NULL);
    int64_t current_time = (getTime.tv_sec + 100) * 1000 + getTime.tv_usec / 1000;
    if (current_time < 0) {
        current_time = 0;
    }
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);

    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId1, static_cast<uint64_t>(current_time));
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(g_data1 == 1);

    ret = TimeServiceClient::GetInstance()->StopTimer(timerId1);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: ProxyTimer001.
* @tc.desc: proxy timer.
* @tc.type: FUNC
* @tc.require: SR000H0GQ6 AR000H2VTQ
*/
HWTEST_F(TimeServiceTest, ProxyTimer001, TestSize.Level0)
{
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
    TimeSaDeathRecipient recipient;
    recipient.OnRemoteDied(nullptr);
    TimeServiceClient::GetInstance()->OnRemoteSaDied(nullptr);
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
}