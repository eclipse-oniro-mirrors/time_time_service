/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <unistd.h>
#include "timer_manager.h"
#include "timer_proxy.h"
#include "time_common.h"
#include "time_service_test.h"
#include "timer_info_test.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace std::chrono;

namespace {
constexpr int ONE_HUNDRED = 100;
constexpr uint64_t MICRO_TO_MILLISECOND = 1000;
const uint64_t TIMER_ID = 88887;
const int UID = 999996;
const int PID = 999997;
const int ELAPSED_REALTIME_WAKEUP = 2;

}
TimerManager* timerManagerHandler_ = nullptr;

class TimeProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void TimeProxyTest::SetUpTestCase(void)
{}

void TimeProxyTest::TearDownTestCase(void)
{}

void TimeProxyTest::SetUp(void)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "start SetUp.");
    timerManagerHandler_ = TimerManager::GetInstance();
    EXPECT_NE(timerManagerHandler_, nullptr);
    TIME_HILOGI(TIME_MODULE_SERVICE, "end SetUp.");
}

void TimeProxyTest::TearDown(void)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "start TearDown.");
    timerManagerHandler_ = nullptr;
    TIME_HILOGI(TIME_MODULE_SERVICE, "end TearDown.");
}

uint64_t CreateTimer(int uid, int pid)
{
    TimerPara paras;
    paras.timerType = ELAPSED_REALTIME_WAKEUP;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    return timerId;
}

uint64_t StartTimer(uint64_t timerId)
{
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    uint64_t triggerTime = 10000000 + bootTime;
    auto ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    return triggerTime;
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
        usleep(MICRO_TO_MILLISECOND);
    }
}

/**
* @tc.name: UidTimerMap001
* @tc.desc: Test UID timer map management - timer addition on start and removal on stop
* @tc.precon: Timer proxy service is available, UID timer map is accessible
* @tc.step: 1. Create and start timer for specific UID and PID
*           2. Verify timer is added to UID timer map with correct structure
*           3. Stop timer and verify removal from UID timer map
*           4. Destroy timer
* @tc.expect: Timer is properly added to UID map on start, completely removed on stop
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, UidTimerMap001, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);
    StartTimer(timerId);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)1);
    
    auto itUidTimerMap = uidTimersMap.find(uid);
    EXPECT_NE(itUidTimerMap, uidTimersMap.end());
    EXPECT_EQ(itUidTimerMap->second.size(), (const unsigned int)1);
    
    auto itTimerId = itUidTimerMap->second.find(timerId);
    EXPECT_NE(itTimerId, itUidTimerMap->second.end());
    EXPECT_NE(itTimerId->second, nullptr);

    auto ret = timerManagerHandler_->StopTimer(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);

    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: UidTimerMap002
* @tc.desc: Test UID timer map management - timer removal on destruction
* @tc.precon: Timer proxy service is available, UID timer map is accessible
* @tc.step: 1. Create and start timer for specific UID and PID
*           2. Destroy timer without explicit stop
*           3. Verify timer is removed from UID timer map
* @tc.expect: Timer is properly removed from UID map upon destruction
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, UidTimerMap002, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);
    StartTimer(timerId);

    auto ret = timerManagerHandler_->DestroyTimer(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)0);
}

/**
* @tc.name: UidTimerMap003
* @tc.desc: Test UID timer map management - timer removal on trigger completion
* @tc.precon: Timer proxy service is available, callback mechanism works
* @tc.step: 1. Create elapsed realtime wakeup timer with callback
*           2. Start timer with short duration
*           3. Verify timer is added to UID timer map
*           4. Wait for timer trigger and callback execution
*           5. Verify timer is removed from UID timer map after trigger
* @tc.expect: Timer is added to UID map on start, removed after successful trigger
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, UidTimerMap003, TestSize.Level1)
{
    g_data1 = 0;
    int32_t uid = 2000;
    int pid = 1000;
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    uidTimersMap.clear();
    TimerPara paras;
    paras.timerType = ELAPSED_REALTIME_WAKEUP;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    uint64_t timerId = 0;
    timerManagerHandler_->CreateTimer(paras, TimeOutCallbackReturn, wantAgent, uid, pid, timerId, NOT_STORE);

    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    uint64_t triggerTime = ONE_HUNDRED + bootTime;
    auto ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)1);
    WaitForAlarm(&g_data1, ONE_HUNDRED * MICRO_TO_MILLISECOND);
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: ProxyTimerByUid001
* @tc.desc: Test UID-based timer proxy functionality - enable and disable proxy
* @tc.precon: Timer proxy service is available, proxy timer map is accessible
* @tc.step: 1. Enable proxy for specific UID without PID list
*           2. Verify proxy timer map contains UID entry
*           3. Disable proxy for the UID
*           4. Verify proxy timer map is cleared
* @tc.expect: Proxy is successfully enabled and disabled, proxy map is properly updated
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerByUid001, TestSize.Level1)
{
    int32_t uid = 1000;
    bool isProxy = true;
    bool needRetrigger = true;
    std::set<int> pidList;
    bool ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);

    auto key = GetProxyKey(uid, 0);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    isProxy = false;
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)0);
}

/**
* @tc.name: ProxyTimerByUid002
* @tc.desc: Test UID-based timer proxy with active timer - timing adjustment behavior
* @tc.precon: Timer proxy service is available, has active timer for testing
* @tc.step: 1. Create and start timer for specific UID
*           2. Record original trigger time
*           3. Enable proxy for UID
*           4. Verify timer is added to proxy map and timing is adjusted
*           5. Disable proxy and verify timing is restored
* @tc.expect: Proxy adjusts timer timing when enabled, restores original timing when disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerByUid002, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);
    StartTimer(timerId);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    std::chrono::steady_clock::time_point originTime = uidTimersMap[uid][timerId]->whenElapsed;

    std::set<int> pidList;
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    auto key = GetProxyKey(uid, 0);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    it = TimerProxy::GetInstance().proxyTimers_.find(key);
    auto it2 = std::find(it->second.begin(), it->second.end(), timerId);
    EXPECT_NE(it2, it->second.end());
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    std::chrono::steady_clock::time_point time = uidTimersMap[uid][timerId]->originWhenElapsed;
    EXPECT_EQ(originTime, time);
    auto it3 = uidTimersMap.find(uid);
    EXPECT_NE(it3, uidTimersMap.end());
    auto it4 = it3->second.find(timerId);
    EXPECT_NE(it4, it3->second.end());
    EXPECT_NE(it4->second->whenElapsed, time);

    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)0);
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    auto it5 = uidTimersMap.find(uid);
    EXPECT_NE(it5, uidTimersMap.end());
    auto it6 = it5->second.find(timerId);
    EXPECT_NE(it6, it5->second.end());
    EXPECT_EQ(it6->second->whenElapsed, time);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: ProxyTimerByUid003
* @tc.desc: Test multiple UID proxy management and bulk reset functionality
* @tc.precon: Timer proxy service is available, supports multiple UID proxies
* @tc.step: 1. Enable proxy for three different UIDs
*           2. Verify all proxies are recorded in proxy timer map
*           3. Execute bulk reset of all proxies
*           4. Verify proxy timer map is completely cleared
* @tc.expect: Multiple UID proxies are properly managed, bulk reset clears all proxies
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerByUid003, TestSize.Level1)
{
    int32_t uid = 2000;
    std::set<int> pidList;
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    auto key = GetProxyKey(uid, 0);
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 3000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)2);
    key = GetProxyKey(uid, 0);
    it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 4000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)3);
    key = GetProxyKey(uid, 0);
    it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    retProxy = timerManagerHandler_->ResetAllProxy();
    EXPECT_TRUE(retProxy);
    EXPECT_TRUE(TimerProxy::GetInstance().proxyTimers_.empty());
}

/**
* @tc.name: AdjustTimer001
* @tc.desc: Test timer adjustment functionality - enable and disable unified timing
* @tc.precon: Timer proxy service is available, adjustment mechanism works
* @tc.step: 1. Enable timer adjustment with 100ms interval
*           2. Verify adjustment is processed (adjust timer list may be empty initially)
*           3. Disable timer adjustment
*           4. Verify adjustment is properly cleared
* @tc.expect: Timer adjustment is successfully enabled and disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, AdjustTimer001, TestSize.Level1)
{
    /* The system timers can be aligned to a unified time and recorded in adjustTimers_. */
    bool isAdjust = true;
    uint32_t interval = 100;
    bool ret = timerManagerHandler_->AdjustTimer(isAdjust, interval, 0);
    EXPECT_TRUE(ret);
    EXPECT_EQ(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);

    /* The unified heartbeat can be deleted successfully and deleted from adjustTimers_. */
    isAdjust = false;
    interval = 0;
    ret = timerManagerHandler_->AdjustTimer(isAdjust, interval, 0);
    EXPECT_TRUE(ret);
    EXPECT_EQ(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
}

/**
* @tc.name: AdjustTimer002
* @tc.desc: Test timer exemption functionality with adjustment
* @tc.precon: Timer proxy service is available, exemption list is configurable
* @tc.step: 1. Create and start timer for specific UID/PID
*           2. Add application to timer exemption list
*           3. Verify exemption list is updated
*           4. Enable timer adjustment
*           5. Verify exempted timer is not included in adjustment
* @tc.expect: Exempted applications are excluded from unified timing adjustments
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, AdjustTimer002, TestSize.Level1)
{
    int32_t uid = 2000;
    int32_t pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);

    /* Create a timer */
    StartTimer(timerId);

    /* Exempt the timer of the app and update the record to adjustExemptionList_. */
    std::unordered_set<std::string> nameArr{"time_service"};
    timerManagerHandler_->SetTimerExemption(nameArr, true);
    EXPECT_NE(TimerProxy::GetInstance().adjustExemptionList_.size(), (const unsigned int)0);

    /* Unified heartbeat is triggered. The heartbeat of exempted applications is not unified. */
    bool isAdjust = true;
    uint32_t interval = 200;
    bool adjustRet = timerManagerHandler_->AdjustTimer(isAdjust, interval, 0);
    EXPECT_TRUE(adjustRet);
    EXPECT_NE(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: ProxyTimerByPid001
* @tc.desc: Test PID-based timer proxy functionality - enable and disable proxy
* @tc.precon: Timer proxy service is available, supports PID-level proxy
* @tc.step: 1. Enable proxy for specific PID within UID
*           2. Verify proxy timer map contains PID entry
*           3. Disable proxy for the PID
*           4. Verify proxy timer map is cleared
* @tc.expect: PID-based proxy is successfully enabled and disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerByPid001, TestSize.Level1)
{
    int pid = 1003;
    int uid = 2003;
    std::set<int> pidList;
    pidList.insert(pid);
    bool isProxy = true;
    bool needRetrigger = true;
    bool ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    auto key = GetProxyKey(uid, pid);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    isProxy = false;
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)0);
}

/**
* @tc.name: ProxyTimerByPid002
* @tc.desc: Test PID-based timer proxy with active timer - timing adjustment behavior
* @tc.precon: Timer proxy service is available, has active timer for testing
* @tc.step: 1. Create and start timer for specific UID/PID
*           2. Record original trigger time
*           3. Enable proxy for specific PID
*           4. Verify timer is added to proxy map and timing is adjusted
*           5. Disable proxy and verify timing is restored
* @tc.expect: PID-based proxy adjusts timer timing when enabled, restores original timing when disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerByPid002, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    std::set<int> pidList;
    pidList.insert(pid);
    uint64_t timerId = CreateTimer(uid, pid);
    uint64_t originTime = StartTimer(timerId);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;

    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto key = GetProxyKey(uid, pid);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    it = TimerProxy::GetInstance().proxyTimers_.find(key);
    auto it2 = std::find(it->second.begin(), it->second.end(), timerId);
    EXPECT_NE(it2, it->second.end());
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    std::chrono::steady_clock::time_point time = uidTimersMap[uid][timerId]->originWhenElapsed;
    EXPECT_EQ(originTime, time.time_since_epoch().count() / NANO_TO_MILESECOND);

    auto it3 = uidTimersMap.find(uid);
    EXPECT_NE(it3, uidTimersMap.end());
    auto it4 = it3->second.find(timerId);
    EXPECT_NE(it4, it3->second.end());
    EXPECT_NE(it4->second->whenElapsed, time);

    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)0);
    uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    auto it5 = uidTimersMap.find(uid);
    EXPECT_NE(it5, uidTimersMap.end());
    auto it6 = it5->second.find(timerId);
    EXPECT_NE(it6, it5->second.end());
    EXPECT_EQ(it6->second->whenElapsed, time);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: PidProxyTimer003
* @tc.desc: Test multiple PID proxy management within same UID and bulk reset
* @tc.precon: Timer proxy service is available, supports multiple PID proxies
* @tc.step: 1. Enable proxy for three different PIDs within same UID
*           2. Verify all PID proxies are recorded in proxy timer map
*           3. Execute bulk reset of all proxies
*           4. Verify all PID proxies are cleared
* @tc.expect: Multiple PID proxies are properly managed within UID, bulk reset clears all
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, PidProxyTimer003, TestSize.Level1)
{
    int uid = 1000;
    int pid1 = 2000;
    std::set<int> pidList;
    pidList.insert(pid1);

    int pid2 = 3000;
    pidList.insert(pid2);

    int pid3 = 4000;
    pidList.insert(pid3);
    
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)3);
    uint64_t key1 = GetProxyKey(uid, pid1);
    uint64_t key2 = GetProxyKey(uid, pid2);
    uint64_t key3 = GetProxyKey(uid, pid3);
    auto it = TimerProxy::GetInstance().proxyTimers_.find(key1);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
    it = TimerProxy::GetInstance().proxyTimers_.find(key2);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
    it = TimerProxy::GetInstance().proxyTimers_.find(key3);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    retProxy = timerManagerHandler_->ResetAllProxy();
    EXPECT_TRUE(retProxy);
    EXPECT_TRUE(TimerProxy::GetInstance().proxyTimers_.empty());
}

/**
* @tc.name: PidProxyTimer004
* @tc.desc: Test PID proxy isolation between different UIDs with same PID
* @tc.precon: Timer proxy service is available, supports UID-level isolation
* @tc.step: 1. Create timers for two different UIDs with same PID
*           2. Enable proxy for first UID only
*           3. Verify only first UID's timer is proxied
*           4. Check proxy status for both UIDs
* @tc.expect: PID proxy is UID-specific, enabling for one UID doesn't affect other UIDs
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, PidProxyTimer004, TestSize.Level1)
{
    int32_t uid1 = 2000;
    int32_t uid2 = 2001;
    int pid = 1000;
    uint64_t timerId1 = CreateTimer(uid1, pid);
    uint64_t timerId2 = CreateTimer(uid2, pid);

    StartTimer(timerId1);
    StartTimer(timerId2);

    std::set<int> pidList;
    pidList.insert(pid);
    /* proxy uid1 expect proxyTimers_ only has one element */
    auto ret = timerManagerHandler_->ProxyTimer(uid1, pidList, true, true);
    EXPECT_TRUE(ret);
    uint64_t key = GetProxyKey(uid1, pid);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_[key].size(), (const unsigned int)1);
    EXPECT_EQ(TimerProxy::GetInstance().IsProxy(uid1, pid), true);
    EXPECT_EQ(TimerProxy::GetInstance().IsProxy(uid2, pid), false);
    timerManagerHandler_->DestroyTimer(timerId1);
    timerManagerHandler_->DestroyTimer(timerId2);
}

/**
* @tc.name: PidProxyTimer005
* @tc.desc: Test PID proxy with needRetrigger=false - timer removal behavior
* @tc.precon: Timer proxy service is available, supports retrigger configuration
* @tc.step: 1. Clear existing proxies and UID timer map
*           2. Create and start timer for specific UID/PID
*           3. Enable proxy with needRetrigger=false
*           4. Verify timer is removed from UID timer map
* @tc.expect: When needRetrigger is false, timer is removed from UID map upon proxy
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, PidProxyTimer005, TestSize.Level1)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "PidProxyTimer005 start");
    auto ret = timerManagerHandler_->ResetAllProxy();
    TimerProxy::GetInstance().uidTimersMap_.clear();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);
    StartTimer(timerId);

    std::set<int> pidList;
    pidList.insert(pid);

    ret = timerManagerHandler_->ProxyTimer(uid, pidList, true, false);
    EXPECT_TRUE(ret);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    auto it1 = uidTimersMap.find(uid);
    EXPECT_EQ(it1, uidTimersMap.end());
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: AdjustTimerProxy001
* @tc.desc: Test timer adjustment behavior with proxy disabled
* @tc.precon: Timer proxy service is available, adjustment and proxy features work
* @tc.step: 1. Create timer and clear existing maps
*           2. Start timer and verify UID map recording
*           3. Enable proxy and verify proxy map recording
*           4. Disable proxy and verify proxy map clearance
*           5. Enable timer adjustment and verify adjustment processing
* @tc.expect: Timer adjustment works independently of proxy status after proxy is disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, AdjustTimerProxy001, TestSize.Level1)
{
    int32_t uid = 2001;
    int pid = 1111;
    std::set<int> pidList;
    pidList.insert(pid);
    uint64_t timerId =  CreateTimer(uid, pid);

    /* clear pidTimersMap_ */
    TimerProxy::GetInstance().uidTimersMap_.clear();
    TimerProxy::GetInstance().proxyTimers_.clear();
    
    /* Start a timer. The timer can be started successfully and can be recorded in pidTimerMap_. */
    StartTimer(timerId);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);

    /* The proxy of a timer is successful and can be recorded in proxyPid_. */
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)1);
    uint64_t key = GetProxyKey(uid, pid);
    auto it = TimerProxy::GetInstance().proxyTimers_.find(key);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    /* Cancel a proxy timer. The proxy is canceled successfully, and the proxyPid_ table is updated. */
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)0);

    /* After the proxy is disabled, determine whether unified heartbeat is required again. */
    bool isAdjust = true;
    uint32_t interval = 300;
    bool adjret = timerManagerHandler_->AdjustTimer(isAdjust, interval, 0);
    EXPECT_TRUE(adjret);
    EXPECT_NE(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: AdjustTimerExemption001
* @tc.desc: Test timer exemption list functionality
* @tc.precon: Timer proxy service is available, exemption list is configurable
* @tc.step: 1. Add bundle and timer name to exemption set
*           2. Create timer info matching exemption criteria
*           3. Verify timer is identified as exempted
* @tc.expect: Timer matching exemption criteria is correctly identified as exempted
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeProxyTest, AdjustTimerExemption001, TestSize.Level0)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "AdjustTimerExemption001 start");
    std::unordered_set<std::string> exemptionSet = {"bundleName|name"};
    TimerProxy::GetInstance().SetTimerExemption(exemptionSet, true);
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo("name", 0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
        nullptr, 0, false, 0, 0, "bundleName");
    auto timerInfoPtr = std::make_shared<TimerInfo>(timerInfo);
    auto ret = TimerProxy::GetInstance().IsTimerExemption(timerInfoPtr);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: ProxyTimerCover001
* @tc.desc: Test callback alarm functionality with null input
* @tc.precon: Timer proxy service is available, callback mechanism works
* @tc.step: 1. Call CallbackAlarmIfNeed with nullptr parameter
*           2. Verify function returns appropriate error code
* @tc.expect: Function handles null input gracefully and returns E_TIME_NULLPTR
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover001, TestSize.Level1)
{
    auto res = TimerProxy::GetInstance().CallbackAlarmIfNeed(nullptr);
    EXPECT_EQ(res, E_TIME_NULLPTR);
}

/**
* @tc.name: ProxyTimerCover002
* @tc.desc: Test UID-based proxy timer map cleanup functionality
* @tc.precon: Timer proxy service is available, proxy map management works
* @tc.step: 1. Enable proxy for specific UID
*           2. Execute timer removal from proxy map for the UID
* @tc.expect: Proxy operations complete without errors
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover002, TestSize.Level1)
{
    std::set<int> pidList;
    auto retProxy = timerManagerHandler_->ProxyTimer(UID, pidList, true, true);
    EXPECT_TRUE(retProxy);
    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(0, UID, 0);
}

/**
* @tc.name: ProxyTimerCover003
* @tc.desc: Test PID-based proxy timer map cleanup functionality
* @tc.precon: Timer proxy service is available, supports PID-level proxy
* @tc.step: 1. Clear existing maps
*           2. Enable proxy for specific PID within UID
*           3. Execute timer removal from proxy map for the PID
* @tc.expect: PID-based proxy operations complete without errors
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover003, TestSize.Level1)
{
    TimerProxy::GetInstance().uidTimersMap_.clear();
    TimerProxy::GetInstance().proxyTimers_.clear();
    int uid = 2000;
    std::set<int> pidList;
    pidList.insert(PID);
    auto retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(0, uid, PID);
}

/**
* @tc.name: ProxyTimerCover004
* @tc.desc: Test UID timer map record and removal functionality
* @tc.precon: Timer proxy service is available, UID map management works
* @tc.step: 1. Test record and remove with null timer info
*           2. Create valid timer info and record in UID map
*           3. Verify timer is properly recorded
*           4. Remove timer from UID map and verify clearance
* @tc.expect: UID timer map properly manages timer records for addition and removal
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover004, TestSize.Level1)
{
    TimerProxy::GetInstance().RecordUidTimerMap(nullptr, false);
    TimerProxy::GetInstance().RemoveUidTimerMap(nullptr);

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, UID, PID, "");
    TimerProxy::GetInstance().RecordUidTimerMap(timerInfo, false);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().uidTimersMutex_);
        auto it = TimerProxy::GetInstance().uidTimersMap_.find(UID);
        EXPECT_NE(it, TimerProxy::GetInstance().uidTimersMap_.end());
    }
    TimerProxy::GetInstance().RemoveUidTimerMap(timerInfo);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().uidTimersMutex_);
        auto it = TimerProxy::GetInstance().uidTimersMap_.find(UID);
        EXPECT_EQ(it, TimerProxy::GetInstance().uidTimersMap_.end());
    }
}

/**
* @tc.name: SetAdjustPolicy001
* @tc.desc: Test adjust policy.
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Setting policies for adjusting timers.
* @tc.expect: Adjusted timer policy takes effect, callback is executed
* @tc.type: FUNC
* @tc.require: issue#851
* @tc.level: level1
*/
HWTEST_F(TimeProxyTest, SetAdjustPolicy001, TestSize.Level1)
{
    std::unordered_map<std::string, uint32_t> policyMap{ {"timer", 1} };
    TimerProxy::GetInstance().SetAdjustPolicy(policyMap);
    EXPECT_EQ(TimerProxy::GetInstance().adjustPolicyList_["timer"], 1);
}
}  // MiscServices
}  // OHOS