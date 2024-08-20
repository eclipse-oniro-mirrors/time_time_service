/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "time_service.h"
#include <cstddef>

using namespace std;
using namespace testing::ext;

namespace NativeTest {
class TimeServiceNativeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
};

/**
* @tc.name: GetTimeZone001
* @tc.desc: Test success status for OH_TimeService_GetTimeZone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceNativeTest, GetTimeZone001, TestSize.Level0)
{
    int len = 40;
    char *bufTmp = static_cast<char *>(malloc(len));
    auto ret = OH_TimeService_GetTimeZone(bufTmp, len);
    EXPECT_EQ(ret, TIMESERVICE_ERR_OK);
}

/**
* @tc.name: GetTimeZone002
* @tc.desc: Test failure status for OH_TimeService_GetTimeZone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceNativeTest, GetTimeZone002, TestSize.Level0)
{
    int len = 0;
    char *bufTmp = static_cast<char *>(malloc(len + 1));
    auto ret = OH_TimeService_GetTimeZone(bufTmp, len);
    EXPECT_EQ(ret, TIMESERVICE_ERR_INVALID_PARAMETER);
}

/**
* @tc.name: GetTimeZone003
* @tc.desc: Test failure status for OH_TimeService_GetTimeZone.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceNativeTest, GetTimeZone003, TestSize.Level0)
{
    int len = 100;
    char *bufTmp = NULL;
    auto ret = OH_TimeService_GetTimeZone(bufTmp, len);
    EXPECT_EQ(ret, TIMESERVICE_ERR_INVALID_PARAMETER);
}
}