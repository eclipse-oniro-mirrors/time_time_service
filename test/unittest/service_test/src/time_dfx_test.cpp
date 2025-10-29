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

#define private public
#define protected public
#include "time_system_ability.h"
#undef private
#undef protected

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "time_service_test.h"
#include "timer_info_test.h"
#include "token_setproc.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace OHOS::Security::AccessToken;

constexpr const uint16_t EACH_LINE_LENGTH = 100;
#ifdef HIDUMPER_ENABLE
constexpr const char *CMD = "hidumper -s 3702 -a";
#endif

class TimeDfxTest : public testing::Test {
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
    FILE *ptr = popen(cmd.c_str(), "r");
    if (ptr != nullptr) {
        char buff[EACH_LINE_LENGTH] = { 0x00 };
        while (fgets(buff, sizeof(buff), ptr) != nullptr) {
            result.append(std::string(buff));
        }
        pclose(ptr);
        ptr = nullptr;
    } else {
        return false;
    }
    return true;
}

#ifdef HIDUMPER_ENABLE

/**
* @tc.name: DumpAllTimeInfo001
* @tc.desc: Test dumping all time information via hidumper command
* @tc.precon: Hidumper service is enabled and accessible
* @tc.step: 1. Execute hidumper command with -time parameter
*           2. Capture command output
*           3. Verify output contains time-related information
* @tc.expect: Command executes successfully, output contains "dump all time info" and "dump the time Zone"
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpAllTimeInfo001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(std::string(CMD).append(" -time").c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump all time info"), std::string::npos);
    EXPECT_NE(result.find("dump the time Zone"), std::string::npos);
}

/**
* @tc.name: DumpTimerInfo001
* @tc.desc: Test dumping all timer information via hidumper command
* @tc.precon: Hidumper service is enabled and accessible
* @tc.step: 1. Execute hidumper command with "-timer -a" parameters
*           2. Capture command output
*           3. Verify output contains timer information
* @tc.expect: Command executes successfully, output contains "dump all timer info"
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpTimerInfo001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(std::string(CMD).append(" \"-timer -a\"").c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump all timer info"), std::string::npos);
}

/**
* @tc.name: DumpTimerInfoById001
* @tc.desc: Test dumping specific timer information by timer ID
* @tc.precon: Hidumper service is enabled, timer service is available
* @tc.step: 1. Create a realtime type timer
*           2. Execute hidumper command with specific timer ID
*           3. Capture and verify command output
*           4. Destroy the created timer
* @tc.expect: Timer creation succeeds, command output contains timer details, timer destruction succeeds
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpTimerInfoById001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-timer -i ").append(std::to_string(timerId)).append(" \"");
    auto ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("timer id"), std::string::npos);
    EXPECT_NE(result.find("timer type"), std::string::npos);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpTimerTriggerById001
* @tc.desc: Test dumping timer trigger information by timer ID
* @tc.precon: Hidumper service is enabled, timer service is available
* @tc.step: 1. Create a realtime type timer with interval
*           2. Execute hidumper command with timer trigger parameter
*           3. Capture and verify command output
*           4. Destroy the created timer
* @tc.expect: Timer creation succeeds, command output contains trigger details, timer destruction succeeds
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpTimerTriggerById001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(5);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-timer -s ").append(std::to_string(timerId)).append(" \"");
    auto ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("timer id"), std::string::npos);
    EXPECT_NE(result.find("timer trigger"), std::string::npos);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpShowHelp001
* @tc.desc: Test dumping help information via hidumper command
* @tc.precon: Hidumper service is enabled and accessible
* @tc.step: 1. Execute hidumper command with -h parameter
*           2. Capture command output
*           3. Verify output contains help information for time-related commands
* @tc.expect: Command executes successfully, output contains expected help text for time and timer commands
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpShowHelp001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(std::string(CMD).append(" -h"), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump current time info,include localtime,timezone info"), std::string::npos);
    EXPECT_NE(result.find("dump all timer info"), std::string::npos);
    EXPECT_NE(result.find("dump the timer info with timer id"), std::string::npos);
}

/**
* @tc.name: DumpIdleTimer001
* @tc.desc: Test dumping idle timer information in working state
* @tc.precon: Hidumper service is enabled, system is in working state
* @tc.step: 1. Execute hidumper command with '-idle -a' parameters
*           2. Capture command output
*           3. Verify output indicates system is in working state (idle state = 0)
* @tc.expect: Command executes successfully, output contains "dump idle state = 0" indicating working state
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpIdleTimer001, TestSize.Level0)
{
    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(std::string(CMD).append(" '-idle -a'"), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump idle state         = 0"), std::string::npos);
}

/**
* @tc.name: DumpIdleTimer002
* @tc.desc: Test dumping idle timer information in sleep state with active idle timer
* @tc.precon: Hidumper service is enabled, timer service is available
* @tc.step: 1. Create an idle type timer and start it with future trigger time
*           2. Execute hidumper command with '-idle -a' parameters
*           3. Capture and verify command output
*           4. Destroy the created timer
* @tc.expect: Timer creation and start succeed, command output contains idle timer details
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpIdleTimer002, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_IDLE);
    timerInfo->SetRepeat(false);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + 3000);

    std::string result;
    auto ret = TimeDfxTest::ExecuteCmd(std::string(CMD).append(" '-idle -a'"), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("timer whenElapsed"), std::string::npos);

    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: DumpUidTimerMapInfo001
* @tc.desc: Test dumping UID timer map information via hidumper command
* @tc.precon: Hidumper service is enabled, timer service is available
* @tc.step: 1. Create and start a realtime type timer
*           2. Execute hidumper command with "-UidTimer -l" parameters
*           3. Capture and verify command output
*           4. Destroy the created timer
* @tc.expect: Timer operations succeed, command output contains UID timer map details
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpUidTimerMapInfo001, TestSize.Level0)
{
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-UidTimer -l ").append(" \"");

    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(5);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, time + 3000);
    EXPECT_TRUE(ret);

    ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("* timer id"), std::string::npos);
    EXPECT_NE(result.find("* timer whenElapsed"), std::string::npos);
    TIME_HILOGD(TIME_MODULE_SERVICE, "-UidTimer -l: %{public}s", result.c_str());
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpProxyTimerMapInfo001
* @tc.desc: Test dumping proxy timer map information via hidumper command
* @tc.precon: Hidumper service is enabled, timer service is available
* @tc.step: 1. Create and start a realtime type timer
*           2. Execute hidumper command with "-ProxyTimer -l" parameters
*           3. Capture and verify command output
*           4. Destroy the created timer
* @tc.expect: Timer operations succeed, command output contains proxy timer map details
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpProxyTimerMapInfo001, TestSize.Level0)
{
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-ProxyTimer -l ").append(" \"");

    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(5);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, time + 3000);
    EXPECT_TRUE(ret);

    ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump proxy map"), std::string::npos);
    TIME_HILOGD(TIME_MODULE_SERVICE, "-ProxyTimer -l: %{public}s", result.c_str());
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: DumpProxyDelayTime001
* @tc.desc: Test dumping proxy delay time information via hidumper command
* @tc.precon: Hidumper service is enabled and accessible
* @tc.step: 1. Execute hidumper command with "-ProxyDelayTime -l" parameters
*           2. Capture command output
*           3. Verify output contains expected delay time value
* @tc.expect: Command executes successfully, output contains expected delay time (259200000)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpProxyDelayTime001, TestSize.Level0)
{
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-ProxyDelayTime -l ").append(" \"");
    auto ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("259200000"), std::string::npos);
    TIME_HILOGD(TIME_MODULE_SERVICE, "-ProxyDelayTime -l: %{public}s", result.c_str());
}

/**
* @tc.name: DumpAdjustTime001
* @tc.desc: Test dumping time adjustment information via hidumper command
* @tc.precon: Hidumper service is enabled and accessible
* @tc.step: 1. Execute hidumper command with "-adjust -a" parameters
*           2. Capture command output
*           3. Verify output contains time adjustment information
* @tc.expect: Command executes successfully, output contains "dump adjust time" information
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeDfxTest, DumpAdjustTime001, TestSize.Level0)
{
    std::string result;
    auto CMD1 = std::string(CMD).append(" \"-adjust -a ").append(" \"");
    auto ret = TimeDfxTest::ExecuteCmd(CMD1.c_str(), result);
    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("dump adjust time"), std::string::npos);
    TIME_HILOGD(TIME_MODULE_SERVICE, "-adjust -a: %{public}s", result.c_str());
}

#endif
} // namespace MiscServices
} // namespace OHOS