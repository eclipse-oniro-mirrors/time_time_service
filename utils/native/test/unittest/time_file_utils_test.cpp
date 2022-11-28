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
#include <gtest/gtest.h>
#include "time_file_utils.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;

constexpr const char *DIR = "/data/test/time/tmp_dir";
constexpr const char *FILE = "/data/test/time/tmp_dir/1.txt";
constexpr const char *NEWFILE = "/data/test/time/tmp_dir/2.txt";
class TimeFileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimeFileUtilsTest::SetUpTestCase(void)
{
}

void TimeFileUtilsTest::TearDownTestCase(void)
{
}

void TimeFileUtilsTest::SetUp(void)
{
}

void TimeFileUtilsTest::TearDown(void)
{
}


/**
* @tc.name: MkRecursiveDir001
* @tc.desc: make recursive dir
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, MkRecursiveDir001, TestSize.Level1)
{
    bool ret = TimeFileUtils::MkRecursiveDir(DIR, true);
    EXPECT_EQ(true, ret);
    bool ret1 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(true, ret1);
    bool ret2 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret2);
    bool ret3 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(false, ret3);
}

/**
* @tc.name: MkRecursiveDir002
* @tc.desc: make recursive dir
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, MkRecursiveDir002, TestSize.Level1)
{
    bool ret = TimeFileUtils::MkRecursiveDir(DIR, false);
    EXPECT_EQ(true, ret);
    bool ret1 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(true, ret1);
    bool ret2 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret2);
    bool ret3 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(false, ret3);
}

/**
* @tc.name: MkRecursiveDir003
* @tc.desc: make recursive dir
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, MkRecursiveDir003, TestSize.Level1)
{
    bool ret = TimeFileUtils::MkRecursiveDir(nullptr, false);
    EXPECT_EQ(false, ret);

    bool ret1 = TimeFileUtils::MkRecursiveDir("", false);
    EXPECT_EQ(false, ret1);

    bool ret2 = TimeFileUtils::MkRecursiveDir(nullptr, false);
    EXPECT_EQ(false, ret2);
}

/**
* @tc.name: IsExistDir001
* @tc.desc: is exist dir
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, IsExistDir001, TestSize.Level1)
{
    bool ret = TimeFileUtils::IsExistDir(nullptr);
    EXPECT_EQ(false, ret);

    bool ret1 = TimeFileUtils::IsExistDir("abcdef");
    EXPECT_EQ(false, ret1);
}

/**
* @tc.name: IsExistDir001
* @tc.desc: is exist file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, IsExistFile001, TestSize.Level1)
{
    bool ret = TimeFileUtils::IsExistFile(nullptr);
    EXPECT_EQ(false, ret);

    bool ret1= TimeFileUtils::IsExistFile("abcdef.txt");
    EXPECT_EQ(false, ret1);
}

/**
* @tc.name: RemoveFile001
* @tc.desc: remove file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, RemoveFile001, TestSize.Level1)
{
    system("mkdir /data/test/time/tmp_dir/");
    system("touch /data/test/time/tmp_dir/1.txt");
    bool ret = TimeFileUtils::RemoveFile(file);
    EXPECT_EQ(true, ret);
    bool ret1 = TimeFileUtils::IsExistFile(file);
    EXPECT_EQ(false, ret1);

    bool ret2 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret2);
    bool ret3 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(false, ret3);
}

/**
* @tc.name: RemoveFile002
* @tc.desc: remove file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, RemoveFile002, TestSize.Level1)
{
    bool ret = TimeFileUtils::IsExistDir(FILE);
    EXPECT_EQ(false, ret);
    bool ret1 = TimeFileUtils::RemoveFile(FILE);
    EXPECT_EQ(true, ret1);

    bool ret2 = TimeFileUtils::IsExistDir(DIR);
    EXPECT_EQ(false, ret2);
    bool ret3 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret3);
}

/**
* @tc.name: RenameFile01
* @tc.desc: rename file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, RenameFile001, TestSize.Level1)
{
    bool ret = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret);
    bool ret1 = TimeFileUtils::RenameFile(nullptr, DIR);
    EXPECT_EQ(false, ret1);

    bool ret2 = TimeFileUtils::RenameFile(DIR, nullptr);
    EXPECT_EQ(false, ret2);

    bool ret3 = TimeFileUtils::RenameFile(DIR, FILE);
    EXPECT_EQ(false, ret3);

    system("mkdir /data/test/time/tmp_dir/");
    system("touch /data/test/time/tmp_dir/1.txt");
    bool ret4 = TimeFileUtils::RenameFile(FILE, NEWFILE);
    EXPECT_EQ(true, ret4);

    bool ret5 = TimeFileUtils::RemoveFile(NEWFILE);
    EXPECT_EQ(true, ret5);

    bool ret6 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret6);
}

/**
* @tc.name: ChownFile001
* @tc.desc: chown file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, ChownFile001, TestSize.Level1)
{
    system("mkdir /data/test/time/tmp_dir/");
    system("touch /data/test/time/tmp_dir/1.txt");
    bool ret = TimeFileUtils::IsExistFile(FILE);
    EXPECT_EQ(true, ret);
    bool ret1 = TimeFileUtils::ChownFile(FILE, 0, 0);
    EXPECT_EQ(true, ret1);
    bool ret2 = TimeFileUtils::RemoveFile(FILE);
    EXPECT_EQ(true, ret2);
    bool ret3 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret3);
}

/**
* @tc.name: WriteFile001
* @tc.desc: chown file
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, WriteFile001, TestSize.Level1)
{
    system("mkdir /data/test/time/tmp_dir/");
    system("touch /data/test/time/tmp_dir/1.txt");
    const char buffer[1024] = "test";
    bool ret = TimeFileUtils::WriteFile(nullptr, buffer, 512);
    EXPECT_EQ(false, ret);

    bool ret1 = TimeFileUtils::WriteFile(FILE, nullptr, 512);
    EXPECT_EQ(false, ret1);

    bool ret2 = TimeFileUtils::WriteFile(FILE, buffer, 0);
    EXPECT_EQ(false, ret2);

    bool ret3 = TimeFileUtils::WriteFile(FILE, buffer, 512);
    EXPECT_EQ(true, ret3);

    bool ret4 = TimeFileUtils::RemoveFile(FILE);
    EXPECT_EQ(true, ret4);
    bool ret5 = TimeFileUtils::RemoveFile(DIR);
    EXPECT_EQ(true, ret5);
}

/**
* @tc.name: IsValidPath001
* @tc.desc: is valid path
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, IsValidPath001, TestSize.Level1)
{
    bool ret = TimeFileUtils::IsValidPath("/data/", "/data/");
    EXPECT_EQ(true, ret);

    bool ret1 = TimeFileUtils::IsValidPath("/data/", "/");
    EXPECT_EQ(false, ret1);

    bool ret2 = TimeFileUtils::IsValidPath("..", "/data/");
    EXPECT_EQ(false, ret2);

    bool ret3 = TimeFileUtils::IsValidPath("data", "..");
    EXPECT_EQ(false, ret3);

    bool ret4 = TimeFileUtils::IsValidPath("/data", "..");
    EXPECT_EQ(false, ret4);

    bool ret5 = TimeFileUtils::IsValidPath("data", "data");
    EXPECT_EQ(false, ret5);
}

/**
* @tc.name: GetPathDir001
* @tc.desc: get path dir
* @tc.type: FUNC
*/
HWTEST_F(TimeFileUtilsTest, GetPathDir001, TestSize.Level1)
{
    std::string ret = TimeFileUtils::GetPathDir("data");
    EXPECT_EQ(std::string(), ret);

    std::string ret1 = TimeFileUtils::GetPathDir("data/");
    EXPECT_EQ(std::string("data/"), ret1);
}
}