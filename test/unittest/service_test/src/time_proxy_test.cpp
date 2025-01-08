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

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace std::chrono;

namespace {
constexpr uint64_t NANO_TO_MILESECOND = 100000;
constexpr int BLOCK_TEST_TIME = 100000;
const uint64_t TIMER_ID = 88887;
const int UID = 999996;
const int PID = 999997;
const int UID_PROXY_OFFSET = 32;
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
    usleep(BLOCK_TEST_TIME);
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
    paras.timerType = 2;
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

void StartTimer(uint64_t timerId)
{
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    auto ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
}

uint64_t GetProxyKey(int uid, int pid)
{
    uint64_t key = (static_cast<uint64_t>(uid) << UID_PROXY_OFFSET) | static_cast<uint64_t>(pid);
    return key;
}

/**
* @tc.name: UidTimerMap001
* @tc.desc: start a timer, it can be added into UidTimerMap
            and can be erase when stop.
* @tc.type: FUNC
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
* @tc.desc: start a timer, it can be added into UidTimerMap
            and can be erase when destory.
* @tc.type: FUNC
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
* @tc.desc: start a timer, it can be added into UidTimerMap
            and can be erase when triggered.
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, UidTimerMap003, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = CreateTimer(uid, pid);
    usleep(BLOCK_TEST_TIME);
    
    StartTimer(timerId);
    usleep(BLOCK_TEST_TIME);

    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    std::shared_ptr<Batch> batch = timerManagerHandler_->alarmBatches_.at(0);
    std::chrono::steady_clock::time_point tpRpoch(nanoseconds(1000000000));
    batch->start_ = tpRpoch;
    auto retTrigger = timerManagerHandler_->TriggerTimersLocked(triggerList, timerManagerHandler_->GetBootTimeNs());
    EXPECT_EQ(retTrigger, true);
    usleep(BLOCK_TEST_TIME);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    EXPECT_EQ(uidTimersMap.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: ProxyTimerByUid001
* @tc.desc: test proxytimer in uid
* @tc.type: FUNC
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
* @tc.desc: test proxy by uid, the map proxyTimers_ acts.
* @tc.type: FUNC
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
* @tc.desc: reset all proxy
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerByUid003, TestSize.Level1)
{
    int32_t uid = 2000;
    std::set<int> pidList;
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto it = proxyTimers.find(uid);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 3000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)2);
    it = proxyTimers.find(uid);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 4000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)3);
    it = proxyTimers.find(uid);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    retProxy = timerManagerHandler_->ResetAllProxy();
    EXPECT_TRUE(retProxy);
    EXPECT_TRUE(proxyTimers.empty());
}


/**
* @tc.name: AdjustTimer001
* @tc.desc: adjust timer test
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, AdjustTimer001, TestSize.Level1)
{
    /* The system timers can be aligned to a unified time and recorded in adjustTimers_. */
    bool isAdjust = true;
    uint32_t interval = 100;
    bool ret = timerManagerHandler_->AdjustTimer(isAdjust, interval);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);

    /* The unified heartbeat can be deleted successfully and deleted from adjustTimers_. */
    isAdjust = false;
    interval = 0;
    ret = timerManagerHandler_->AdjustTimer(isAdjust, interval);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
}

/**
* @tc.name: AdjustTimer002
* @tc.desc: set timer exemption
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, AdjustTimer002, TestSize.Level1)
{
    /* Create a timer with windowLen set to 0. */
    TimerPara paras{.timerType = 2, .windowLength = 0, .interval = 0, .flag = 0};
    auto wantAgent = std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int32_t pid = 1000;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                     wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* Create a timer */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* Exempt the timer of the app and update the record to adjustExemptionList_. */
    std::unordered_set<std::string> nameArr{"time_service"};
    timerManagerHandler_->SetTimerExemption(nameArr, true);
    usleep(BLOCK_TEST_TIME);
    EXPECT_NE(TimerProxy::GetInstance().adjustExemptionList_.size(), (const unsigned int)0);

    /* Unified heartbeat is triggered. The heartbeat of exempted applications is not unified. */
    bool isAdjust = true;
    uint32_t interval = 200;
    bool adjustRet = timerManagerHandler_->AdjustTimer(isAdjust, interval);
    EXPECT_TRUE(adjustRet);
    usleep(BLOCK_TEST_TIME);
    EXPECT_NE(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
    bool isExemption = true;
    for (auto timer : TimerProxy::GetInstance().adjustTimers_) {
        if (timer->bundleName == "time_service") {
            isExemption = false;
        }
    }
    EXPECT_TRUE(isExemption);
}

/**
* @tc.name: ProxyTimerByPid001
* @tc.desc: test proxytimer in Pid
* @tc.type: FUNC
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
* @tc.desc: test proxy by pid, the map proxyTimers_ acts.
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerByPid002, TestSize.Level1)
{
    int32_t uid = 2000;
    int pid = 1000;
    std::set<int> pidList;
    pidList.insert(pid);
    uint64_t timerId = CreateTimer(uid, pid);
    StartTimer(timerId);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    std::chrono::steady_clock::time_point originTime = uidTimersMap[uid][timerId]->whenElapsed;

    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    auto proxyTimers = TimerProxy::GetInstance().proxyTimers_;
    EXPECT_EQ(proxyTimers.size(), (const unsigned int)1);
    auto key = GetProxyKey(uid, pid);
    auto it = proxyTimers.find(key);
    EXPECT_NE(it, proxyTimers.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

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
* @tc.name: PidProxyTimer003
* @tc.desc: reset all proxy测试
* @tc.type: FUNC
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
    usleep(BLOCK_TEST_TIME);
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
* @tc.desc: test proxy of same pid but different uid.
* @tc.type: FUNC
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
}

/**
* @tc.name: AdjustTimerProxy001
* @tc.desc: Determine whether to unify the heartbeat when the timer proxy is disabled.
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, AdjustTimerProxy001, TestSize.Level1)
{
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2001;
    int pid = 1111;
    std::set<int> pidList;
    pidList.insert(pid);
    uint64_t timerId = 0;

    /* clear pidTimersMap_ */
    TimerProxy::GetInstance().uidTimersMap_.clear();
    TimerProxy::GetInstance().proxyTimers_.clear();

    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    
    /* Start a timer. The timer can be started successfully and can be recorded in pidTimerMap_. */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);

    /* The proxy of a timer is successful and can be recorded in proxyPid_. */
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)1);
    uint64_t key = GetProxyKey(uid, pid);
    auto it = TimerProxy::GetInstance().proxyTimers_.find(key);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    /* Cancel a proxy timer. The proxy is canceled successfully, and the proxyPid_ table is updated. */
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)0);

    /* After the proxy is disabled, determine whether unified heartbeat is required again. */
    bool isAdjust = true;
    uint32_t interval = 300;
    bool adjret = timerManagerHandler_->AdjustTimer(isAdjust, interval);
    EXPECT_TRUE(adjret);
    EXPECT_NE(TimerProxy::GetInstance().adjustTimers_.size(), (const unsigned int)0);
}

/**
* @tc.name: AdjustTimerExemption001.
* @tc.desc: test adjust timer exemption list.
* @tc.type: FUNC
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
* @tc.desc: test CallbackAlarmIfNeed
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover001, TestSize.Level1)
{
    auto res = TimerProxy::GetInstance().CallbackAlarmIfNeed(nullptr);
    EXPECT_EQ(res, E_TIME_NULLPTR);
}

/**
* @tc.name: ProxyTimerCover002
* @tc.desc: test UID
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover002, TestSize.Level1)
{
    std::set<int> pidList;
    bool retProxy = timerManagerHandler_->ProxyTimer(UID, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int) 1);
        auto it = TimerProxy::GetInstance().proxyTimers_.find(UID);
        EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());
        EXPECT_EQ(it->second.size(), (const unsigned int) 0);
    }

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, false, UID, 0, "");
    auto res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    auto timerInfo2 = std::make_shared<TimerInfo>("", TIMER_ID + 1, 0, duration, timePoint, duration, timePoint,
                                                 duration, nullptr, nullptr, 0, false, UID, 0, "");
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo2);
    EXPECT_EQ(res, E_TIME_OK);

    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    retProxy = timerManagerHandler_->ProxyTimer(UID, pidList, false, true);
    EXPECT_TRUE(retProxy);

    retProxy = timerManagerHandler_->ProxyTimer(UID, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);

    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(0, UID, 0);
}


/**
* @tc.name: ProxyTimerCover003
* @tc.desc: test PID
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover003, TestSize.Level1)
{
    TimerProxy::GetInstance().uidTimersMap_.clear();
    TimerProxy::GetInstance().proxyTimers_.clear();
    int uid = 2000;
    std::set<int> pidList;
    pidList.insert(PID);
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyTimers_.size(), (const unsigned int)1);
    uint64_t key = GetProxyKey(uid, PID);
    auto it = TimerProxy::GetInstance().proxyTimers_.find(key);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyTimers_.end());

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, uid, PID, "");
    auto res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    auto timerInfo2 = std::make_shared<TimerInfo>("", TIMER_ID + 1, 0, duration, timePoint, duration, timePoint,
                                                  duration, nullptr, nullptr, 0, false, uid, PID, "");
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo2);
    EXPECT_EQ(res, E_TIME_OK);

    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);

    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);

    TimerProxy::GetInstance().EraseTimerFromProxyTimerMap(0, uid, PID);
}

/**
* @tc.name: ProxyTimerCover004
* @tc.desc: test CallbackAlarmIfNeed
* @tc.type: FUNC
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

}  // MiscServices
}  // OHOS