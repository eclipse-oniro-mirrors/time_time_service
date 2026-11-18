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
#undef private
#undef protected

#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>

#include "time_cmd_dispatcher.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

#ifdef HIDUMPER_ENABLE
namespace {
constexpr const char *DUMP_ALL_TIME_INFO = "dump all time info";

// Rewind the fd and read all bytes written by the dump command.
std::string ReadBackFile(int fd)
{
    std::string content;
    if (lseek(fd, 0, SEEK_SET) < 0) {
        return content;
    }
    char buf[256] = { 0 };
    ssize_t n = 0;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        content.append(buf, static_cast<size_t>(n));
        if (n < static_cast<ssize_t>(sizeof(buf) - 1)) {
            break;
        }
    }
    return content;
}
}

class TimeDfxDispatchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimeDfxDispatchTest::SetUpTestCase(void)
{
}

void TimeDfxDispatchTest::TearDownTestCase(void)
{
}

void TimeDfxDispatchTest::SetUp(void)
{
    // Register dump commands into the in-process dispatcher singleton. It is
    // idempotent (map::insert on an existing key is a no-op), so repeated
    // SetUp calls across cases are safe.
    TimeSystemAbility::GetInstance()->InitDumpCmd();
}

void TimeDfxDispatchTest::TearDown(void)
{
}

/**
* @tc.name: DfxDispatchHelp001
* @tc.desc: Dispatch with "-h" prints the option table and returns false
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-h"}
*           3. Read back the file content
* @tc.expect: Dispatch returns false and the content contains the "Option" header
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchHelp001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_help_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-h" }));
    EXPECT_FALSE(result);
    std::string content = ReadBackFile(fd);
    EXPECT_NE(content.find("Option"), std::string::npos);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchTime001
* @tc.desc: Dispatch with "-time" runs the registered dump-all-time command
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-time"}
*           3. Read back the file content
* @tc.expect: Dispatch returns true and the content contains the time dump header
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchTime001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_time_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-time" }));
    EXPECT_TRUE(result);
    std::string content = ReadBackFile(fd);
    EXPECT_NE(content.find(DUMP_ALL_TIME_INFO), std::string::npos);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchTimerAll001
* @tc.desc: Dispatch with "-timer -a" runs the dump-all-timer command
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-timer", "-a"}
*           3. Read back the file content
* @tc.expect: Dispatch returns true and the content contains the timer dump header
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchTimerAll001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_timer_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-timer", "-a" }));
    EXPECT_TRUE(result);
    std::string content = ReadBackFile(fd);
    EXPECT_NE(content.find("dump all timer info"), std::string::npos);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchTimerById001
* @tc.desc: Dispatch with "-timer -i <id>" runs the dump-timer-by-id command
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-timer", "-i", "1"}
*           3. Read back the file content
* @tc.expect: Dispatch returns true (timer dump output produced even for unknown id)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchTimerById001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_timerid_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-timer", "-i", "1" }));
    EXPECT_TRUE(result);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchTimerTriggerById001
* @tc.desc: Dispatch with "-timer -s <id>" runs the dump-timer-trigger command
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-timer", "-s", "1"}
* @tc.expect: Dispatch returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchTimerTriggerById001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_timertrig_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-timer", "-s", "1" }));
    EXPECT_TRUE(result);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchIdle001
* @tc.desc: Dispatch with "-idle -a" runs the dump-idle command
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-idle", "-a"}
* @tc.expect: Dispatch returns true
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchIdle001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_idle_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-idle", "-a" }));
    EXPECT_TRUE(result);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchUnknown001
* @tc.desc: Dispatch with an unregistered multi-token option returns false
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with args {"-unknown", "-x"}
* @tc.expect: Dispatch returns false. Note: a single-token arg is NOT used
*             here on purpose - getCmdTitle produces an empty title for
*             single-token args and "-time" registers under the same empty
*             key, so single-token dispatch always matches "-time".
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchUnknown001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_unknown_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>({ "-unknown", "-x" }));
    EXPECT_FALSE(result);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DfxDispatchEmpty001
* @tc.desc: Dispatch with empty args prints help and returns false
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Dispatch with an empty args vector
* @tc.expect: Dispatch returns false and the help header is printed
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DfxDispatchEmpty001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dispatch_empty_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    auto result = TimeCmdDispatcher::GetInstance().Dispatch(fd, std::vector<std::string>());
    EXPECT_FALSE(result);
    std::string content = ReadBackFile(fd);
    EXPECT_NE(content.find("Option"), std::string::npos);
    close(fd);
    unlink(path);
}

/**
* @tc.name: DumpEntry001
* @tc.desc: TimeSystemAbility::Dump converts u16string args and forwards to the dispatcher
* @tc.precon: Dump commands are registered in the in-process dispatcher
* @tc.step: 1. Create a temp file and get its fd
*           2. Call TimeSystemAbility::Dump with u16string args {"-time"}
*           3. Read back the file content
* @tc.expect: Dump returns ERR_OK and the content contains the time dump header
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimeDfxDispatchTest, DumpEntry001, TestSize.Level1)
{
    char path[] = "/data/local/tmp/dfx_dump_entry_XXXXXX";
    int fd = mkstemp(path);
    ASSERT_GE(fd, 0);
    std::vector<std::u16string> args;
    args.emplace_back(u"-time");
    auto result = TimeSystemAbility::GetInstance()->Dump(fd, args);
    EXPECT_EQ(result, ERR_OK);
    std::string content = ReadBackFile(fd);
    EXPECT_NE(content.find(DUMP_ALL_TIME_INFO), std::string::npos);
    close(fd);
    unlink(path);
}
#endif // HIDUMPER_ENABLE
} // namespace MiscServices
} // namespace OHOS
