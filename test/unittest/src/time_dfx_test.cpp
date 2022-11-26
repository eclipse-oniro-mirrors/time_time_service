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
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <string>

#include "securec.h"
#include "time_service_test.h"
#include "timer_info_test.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;

constexpr const uint16_t EACH_LINE_LENGTH = 100;
constexpr const uint16_t TOTAL_LENGTH = 1000;
constexpr const char *CMD1 = "hidumper -s 3702 -a -time";
constexpr const char *CMD2 = "hidumper -s 3702 -a \"-timer -a\"";
constexpr const char *CMD3 = "hidumper -s 3702 -a \"-timer -i\"";
constexpr const char *CMD4 = "hidumper -s 3702 -a \"-timer -s\"";
constexpr const char *CMD5 = "hidumper -s 3702 -a -h";

class TimeDfxTest : public testing::Test
{
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static bool ExecuteCmd(const std::string &cmd, std::string &result);
    void SetUp();
    void TearDown();
};

void TimeDfxTest::SetUpTestCase(void)
{
}

void TimeDfxTest::TearDownTestCase(void)
{
}

void TimeDfxTest::SetUp(void)
{
}

void TimeDfxTest::TearDown(void)
{
}

bool TimeDfxTest::ExecuteCmd(const std::string &cmd, std::string &result)
{
    char buff[EACH_LINE_LENGTH] = { 0x00 };
    char output[TOTAL_LENGTH] = { 0x00 };
    FILE *ptr = popen(cmd.c_str(), "r");
    if (ptr != nullptr) {
        while (fgets(buff, sizeof(buff), ptr) != nullptr) {
            if (strcat_s(output, sizeof(output), buff) != 0) {
                pclose(ptr);
                ptr = nullptr;
                return false;
            }
        }
        pclose(ptr);
        ptr = nullptr;
    } else {
        return false;
    }
    result = std::string(output);
    return true;
}

/**
* @tc.name: DumpAllTimeInfo001
* @tc.desc: dump all time info
* @tc.type: FUNC
*/
HWTEST_F(TimeDfxTest, DumpAllTimeInfo001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(CMD1, result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump all time info"), std::string::npos);
    EXPECT_NE(result.find("dump the time Zone"), std::string::npos);
}

/**
* @tc.name: DumpTimerInfo001
* @tc.desc: dump timer info
* @tc.type: FUNC
*/
HWTEST_F(TimeDfxTest, DumpTimerInfo001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(CMD2, result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump all timer info"), std::string::npos);
}

/**
* @tc.name: DumpTimerInfoById001
* @tc.desc: dump timer info by id
* @tc.type: FUNC
*/
HWTEST_F(TimeDfxTest, DumpTimerInfoById001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(CMD3, result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("timer id"), std::string::npos);
    EXPECT_NE(result.find("timer type"), std::string::npos);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpTimerTriggerById001
* @tc.desc: dump trigger by id
* @tc.type: FUNC
*/
HWTEST_F(TimeDfxTest, DumpTimerTriggerById001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(5);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId1 = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_TRUE(timerId1 > 0);
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(CMD4, result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("timer id"), std::string::npos);
    EXPECT_NE(result.find("timer type"), std::string::npos);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId1);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpShowHelp001
* @tc.desc: dump show help
* @tc.type: FUNC
*/
HWTEST_F(TimeDfxTest, DumpShowHelp001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(CMD5, result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump current time info,include localtime,timezone info"), std::string::npos);
    EXPECT_NE(result.find("dump all timer info"), std::string::npos);
    EXPECT_NE(result.find("dump the timer info with timer id"), std::string::npos);
}
} // namespace MiscServices
} // namespace OHOS