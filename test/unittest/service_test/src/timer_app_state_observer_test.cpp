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

#include <gtest/gtest.h>

#include <string>
#include <vector>

#define private public
#define protected public
#include "timer_app_state_observer.h"
#undef private
#undef protected

namespace OHOS {
namespace MiscServices {
namespace {

using namespace testing;
using namespace testing::ext;

class TimerAppStateObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimerAppStateObserverTest::SetUpTestCase(void) {}

void TimerAppStateObserverTest::TearDownTestCase(void) {}

void TimerAppStateObserverTest::SetUp() {}

void TimerAppStateObserverTest::TearDown()
{
    auto observer = TimerAppStateObserver::GetInstance();
    observer->isRegistered_ = false;
    observer->stateCallback_ = nullptr;
}

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Test GetInstance returns valid singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, GetInstance_001, TestSize.Level1)
{
    auto instance1 = TimerAppStateObserver::GetInstance();
    auto instance2 = TimerAppStateObserver::GetInstance();
    ASSERT_NE(instance1, nullptr);
    ASSERT_NE(instance2, nullptr);
    EXPECT_EQ(instance1.GetRefPtr(), instance2.GetRefPtr());
}

/**
 * @tc.name: OnAppStarted_001
 * @tc.desc: Test OnAppStarted triggers callback with isRunning=true
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, OnAppStarted_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.test.app";

    std::string receivedBundleName;
    bool receivedIsRunning = false;
    bool callbackCalled = false;

    observer->stateCallback_ = [&](const std::string& bundleName, bool isRunning) {
        callbackCalled = true;
        receivedBundleName = bundleName;
        receivedIsRunning = isRunning;
    };

    observer->OnAppStarted(appStateData);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedBundleName, "com.test.app");
    EXPECT_TRUE(receivedIsRunning);

    observer->stateCallback_ = nullptr;
}

/**
 * @tc.name: OnAppStopped_001
 * @tc.desc: Test OnAppStopped triggers callback with isRunning=false
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, OnAppStopped_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.test.app";

    std::string receivedBundleName;
    bool receivedIsRunning = true;
    bool callbackCalled = false;

    observer->stateCallback_ = [&](const std::string& bundleName, bool isRunning) {
        callbackCalled = true;
        receivedBundleName = bundleName;
        receivedIsRunning = isRunning;
    };

    observer->OnAppStopped(appStateData);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedBundleName, "com.test.app");
    EXPECT_FALSE(receivedIsRunning);

    observer->stateCallback_ = nullptr;
}

/**
 * @tc.name: Unregister_001
 * @tc.desc: Test Unregister when not registered
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, Unregister_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    observer->isRegistered_ = false;
    observer->Unregister();
    EXPECT_FALSE(observer->isRegistered_);
}

/**
 * @tc.name: Unregister_002
 * @tc.desc: Test Unregister when registered, ResetState should be called
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, Unregister_002, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    observer->isRegistered_ = true;
    observer->stateCallback_ = [](const std::string&, bool) {};

    EXPECT_TRUE(observer->isRegistered_);
    EXPECT_TRUE(observer->stateCallback_ != nullptr);

    // Unregister will call ResetState regardless of AppMgr availability
    observer->Unregister();

    EXPECT_FALSE(observer->isRegistered_);
    EXPECT_TRUE(observer->stateCallback_ == nullptr);
}

/**
 * @tc.name: HandleAppStateChange_001
 * @tc.desc: Test HandleAppStateChange with callback set
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, HandleAppStateChange_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.test.callback";

    std::string receivedBundleName;
    bool receivedIsRunning = false;
    bool callbackCalled = false;

    observer->stateCallback_ = [&](const std::string& bundleName, bool isRunning) {
        callbackCalled = true;
        receivedBundleName = bundleName;
        receivedIsRunning = isRunning;
    };

    observer->OnAppStarted(appStateData);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedBundleName, "com.test.callback");
    EXPECT_TRUE(receivedIsRunning);

    callbackCalled = false;
    observer->OnAppStopped(appStateData);
    EXPECT_TRUE(callbackCalled);
    EXPECT_FALSE(receivedIsRunning);

    observer->stateCallback_ = nullptr;
}

/**
 * @tc.name: HandleAppStateChange_002
 * @tc.desc: Test HandleAppStateChange without callback (should not crash)
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, HandleAppStateChange_002, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.test.nocallback";

    observer->stateCallback_ = nullptr;
    observer->isRegistered_ = true;

    // Should not crash when callback is nullptr
    observer->OnAppStarted(appStateData);

    // State should remain unchanged
    EXPECT_TRUE(observer->isRegistered_);
    EXPECT_TRUE(observer->stateCallback_ == nullptr);

    observer->isRegistered_ = false;
}

/**
 * @tc.name: Register_001
 * @tc.desc: Test Register when already registered
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, Register_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();
    observer->isRegistered_ = true;

    bool result = observer->Register({}, nullptr);
    EXPECT_TRUE(result);
    observer->isRegistered_ = false;
}

/**
 * @tc.name: CallbackWithMultipleApps_001
 * @tc.desc: Test callback with multiple apps
 * @tc.type: FUNC
 */
HWTEST_F(TimerAppStateObserverTest, CallbackWithMultipleApps_001, TestSize.Level1)
{
    auto observer = TimerAppStateObserver::GetInstance();

    std::vector<std::string> startedApps;
    std::vector<std::string> stoppedApps;

    observer->stateCallback_ = [&](const std::string& bundleName, bool isRunning) {
        if (isRunning) {
            startedApps.push_back(bundleName);
        } else {
            stoppedApps.push_back(bundleName);
        }
    };

    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.test.app1";
    observer->OnAppStarted(appStateData);

    appStateData.bundleName = "com.test.app2";
    observer->OnAppStarted(appStateData);

    appStateData.bundleName = "com.test.app1";
    observer->OnAppStopped(appStateData);

    EXPECT_EQ(startedApps.size(), 2u);
    EXPECT_EQ(stoppedApps.size(), 1u);
    EXPECT_EQ(stoppedApps[0], "com.test.app1");

    observer->stateCallback_ = nullptr;
}

} // namespace
} // namespace MiscServices
} // namespace OHOS