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

/**
* @tc.name: UidTimerMap001
* @tc.desc: 启动timer时uid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, UidTimerMap001, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到uidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);
    auto itUidTimerMap = TimerProxy::GetInstance().uidTimersMap_.find(uid);
    EXPECT_NE(itUidTimerMap, TimerProxy::GetInstance().uidTimersMap_.end());
    EXPECT_EQ(itUidTimerMap->second.size(), (const unsigned int)1);
    auto itTimerId = itUidTimerMap->second.find(timerId);
    EXPECT_NE(itTimerId, itUidTimerMap->second.end());
    EXPECT_NE(itTimerId->second, nullptr);

    /* 清理uidTimerMap_，可以清理成功 */
    TimerProxy::GetInstance().uidTimersMap_.clear();
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
    usleep(BLOCK_TEST_TIME);
}

/**
* @tc.name: UidTimerMap002
* @tc.desc: 停止timer时uid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, UidTimerMap002, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到uidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);

    /* 停止一个timer，可以停止成功，可以从uidTimerMap_中删除 */
    ret = timerManagerHandler_->StopTimerInner(timerId, true);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: UidTimerMap003
* @tc.desc: 触发timer时uid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, UidTimerMap003, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到uidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);

    /* 触发一个timer，可以触发成功，可以从uidTimerMap_中删除 */
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    std::shared_ptr<Batch> batch = timerManagerHandler_->alarmBatches_.at(0);
    std::chrono::steady_clock::time_point tpRpoch(nanoseconds(1000000000));
    batch->start_ = tpRpoch;
    auto retTrigger = timerManagerHandler_->TriggerTimersLocked(triggerList, timerManagerHandler_->GetBootTimeNs());
    EXPECT_EQ(retTrigger, true);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: PidTimerMap001
* @tc.desc: 启动timer时pid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidTimerMap001, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1001;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到PidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)1);
    auto itPidTimerMap = TimerProxy::GetInstance().pidTimersMap_.find(pid);
    EXPECT_NE(itPidTimerMap, TimerProxy::GetInstance().pidTimersMap_.end());
    EXPECT_EQ(itPidTimerMap->second.size(), (const unsigned int)1);
    auto itTimerId = itPidTimerMap->second.find(timerId);
    EXPECT_NE(itTimerId, itPidTimerMap->second.end());
    EXPECT_NE(itTimerId->second, nullptr);

    /* 清理pidTimerMap_，可以清理成功 */
    TimerProxy::GetInstance().pidTimersMap_.clear();
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
    usleep(BLOCK_TEST_TIME);
}

/**
* @tc.name: PidTimerMap002
* @tc.desc: 停止timer时pid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidTimerMap002, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = 0;

    /* 清理pidTimersMap_，保证测试前pidTimersMap_内无其他测试中曾记录的pid影响 */
    TimerProxy::GetInstance().pidTimersMap_.clear();

    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到pidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)1);

    /* 停止一个timer，可以停止成功，可以从pidTimerMap_中删除 */
    ret = timerManagerHandler_->StopTimerInner(timerId, true);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: PidTimerMap003
* @tc.desc: 触发timer时pid timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidTimerMap003, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1002;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到pidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)1);

    /* 触发一个timer，可以触发成功，可以从pidTimerMap_中删除 */
    std::vector<std::shared_ptr<TimerInfo>> triggerList;
    std::shared_ptr<Batch> batch = timerManagerHandler_->alarmBatches_.at(0);
    std::chrono::steady_clock::time_point tpRpoch(nanoseconds(1000000000));
    batch->start_ = tpRpoch;
    auto retTrigger = timerManagerHandler_->TriggerTimersLocked(triggerList, timerManagerHandler_->GetBootTimeNs());
    EXPECT_EQ(retTrigger, true);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)0);
    timerManagerHandler_->DestroyTimer(timerId);
}

/**
* @tc.name: ProxyTimer001
* @tc.desc: 代理解代理基本功能测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimer001, TestSize.Level1)
{
    /* 代理一个timer，可以代理成功，可以记录到proxyUid_中 */
    int32_t uid = 1000;
    bool isProxy = true;
    bool needRetrigger = true;
    bool ret = timerManagerHandler_->ProxyTimer(uid, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyUids_.find(uid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    /* 解代理一个timer，可以解代理成功，可以从proxyUid_中删除 */
    isProxy = false;
    ret = timerManagerHandler_->ProxyTimer(uid, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)0);
}

/**
* @tc.name: ProxyTimer002
* @tc.desc: 代理解代理时proxy timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimer002, TestSize.Level1)
{
    /* 创建一个timer，可以创建成功 */
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1000;
    uint64_t timerId = 0;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);

    /* 启动一个timer， 可以启动成功，可以记录到uidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().uidTimersMap_.size(), (const unsigned int)1);
    std::chrono::steady_clock::time_point time = TimerProxy::GetInstance().uidTimersMap_[uid][timerId]->whenElapsed;

    /* 代理一个timer，可以代理成功，可以记录到proxyUid_中 */
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyUids_.find(uid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    /* uidTimerMap_中的触发时间成功更新，proxyUid_中可以记录老的触发时间 */
    it = TimerProxy::GetInstance().proxyUids_.find(uid);
    auto it2 = it->second.find(timerId);
    EXPECT_NE(it2, it->second.end());
    EXPECT_EQ(it2->second, time);

    auto it3 = TimerProxy::GetInstance().uidTimersMap_.find(uid);
    EXPECT_NE(it3, TimerProxy::GetInstance().uidTimersMap_.end());
    auto it4 = it3->second.find(timerId);
    EXPECT_NE(it4, it3->second.end());
    EXPECT_NE(it4->second->whenElapsed, time);

    /* 解代理一个timer，可以解代理成功，可以更新proxyUid_表 */
    ret = timerManagerHandler_->ProxyTimer(uid, false, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)0);

    /* uidTimerMap_中的触发时间被恢复回老的触发时间 */
    auto it5 = TimerProxy::GetInstance().uidTimersMap_.find(uid);
    EXPECT_NE(it5, TimerProxy::GetInstance().uidTimersMap_.end());
    auto it6 = it5->second.find(timerId);
    EXPECT_NE(it6, it5->second.end());
    EXPECT_EQ(it6->second->whenElapsed, time);
    timerManagerHandler_->DestroyTimer(timerId);
    usleep(BLOCK_TEST_TIME);
}

/**
* @tc.name: ProxyTimer003
* @tc.desc: reset all proxy测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimer003, TestSize.Level1)
{
    /* 代理三个timer，可以代理成功，可以记录到proxyUid_中 */
    int32_t uid = 2000;
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyUids_.find(uid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 3000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)2);
    it = TimerProxy::GetInstance().proxyUids_.find(uid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    uid = 4000;
    retProxy = timerManagerHandler_->ProxyTimer(uid, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int)3);
    it = TimerProxy::GetInstance().proxyUids_.find(uid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    /* 可以正常reset，且map会清空 */
    retProxy = timerManagerHandler_->ResetAllProxy();
    EXPECT_TRUE(retProxy);
    EXPECT_TRUE(TimerProxy::GetInstance().proxyUids_.empty());
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
* @tc.name: PidProxyTimer001
* @tc.desc: 代理解代理基本功能测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidProxyTimer001, TestSize.Level1)
{
    /* 代理一个timer，可以代理成功，可以记录到proxyUid_中 */
    int pid = 1003;
    int uid = 2003;
    std::set<int> pidList;
    pidList.insert(pid);
    bool isProxy = true;
    bool needRetrigger = true;
    bool ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyPids_.find(pid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    /* 解代理一个timer，可以解代理成功，可以从proxyPid_中删除 */
    isProxy = false;
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, isProxy, needRetrigger);
    EXPECT_TRUE(ret);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)0);
}

/**
* @tc.name: PidProxyTimer002
* @tc.desc: 代理解代理时proxy timer map数据更新测试
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidProxyTimer002, TestSize.Level1)
{
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid = 2000;
    int pid = 1004;
    std::set<int> pidList;
    pidList.insert(pid);
    uint64_t timerId = 0;

    /* 清理pidTimersMap_，保证测试前pidTimersMap_内无其他测试中曾记录的pid影响 */
    TimerProxy::GetInstance().pidTimersMap_.clear();

    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    
    /* 启动一个timer， 可以启动成功，可以记录到pidTimerMap_中 */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)1);
    std::chrono::steady_clock::time_point time = TimerProxy::GetInstance().pidTimersMap_[pid][timerId]->whenElapsed;

    /* 代理一个timer，可以代理成功，可以记录到proxyPid_中 */
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyPids_.find(pid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    /* pidTimerMap_中的触发时间成功更新，proxyPid_中可以记录老的触发时间 */
    it = TimerProxy::GetInstance().proxyPids_.find(pid);
    auto it2 = it->second.find(timerId);
    EXPECT_NE(it2, it->second.end());
    EXPECT_EQ(it2->second, time);

    auto it3 = TimerProxy::GetInstance().pidTimersMap_.find(pid);
    EXPECT_NE(it3, TimerProxy::GetInstance().pidTimersMap_.end());
    auto it4 = it3->second.find(timerId);
    EXPECT_NE(it4, it3->second.end());
    EXPECT_NE(it4->second->whenElapsed, time);

    /* 解代理一个timer，可以解代理成功，可以更新proxyPid_表 */
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)0);

    /* pidTimerMap_中的触发时间被恢复回老的触发时间 */
    auto it5 = TimerProxy::GetInstance().pidTimersMap_.find(pid);
    EXPECT_NE(it5, TimerProxy::GetInstance().pidTimersMap_.end());
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
    /* 代理三个timer，可以代理成功，可以记录到proxyPid_中 */
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
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)3);
    auto it = TimerProxy::GetInstance().proxyPids_.find(pid1);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    it = TimerProxy::GetInstance().proxyPids_.find(pid2);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    it = TimerProxy::GetInstance().proxyPids_.find(pid3);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)0);

    /* 可以正常reset，且map会清空 */
    retProxy = timerManagerHandler_->ResetAllProxy();
    EXPECT_TRUE(retProxy);
    EXPECT_TRUE(TimerProxy::GetInstance().proxyPids_.empty());
}

/**
* @tc.name: PidProxyTimer004
* @tc.desc: test proxy of same pid but different uid.
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, PidProxyTimer004, TestSize.Level1)
{
    TimerPara paras;
    paras.timerType = 2;
    paras.windowLength = -1;
    paras.interval = 0;
    paras.flag = 0;
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    int32_t uid1 = 2000;
    int32_t uid2 = 2001;
    int pid = 1000;
    uint64_t timerId1 = 0;
    uint64_t timerId2 = 0;

    TimerProxy::GetInstance().pidTimersMap_.clear();
    TimerProxy::GetInstance().proxyPids_.clear();
    /* create timer by uid1 */
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid1, pid, timerId1, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId1, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_[pid].size(), (const unsigned int)1);
    
    /* create timer by uid2 */
    ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid2, pid, timerId2, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId2, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_[pid].size(), (const unsigned int)2);

    std::set<int> pidList;
    pidList.insert(pid);
    /* proxy uid1 expect proxyPids_ only has one element */
    ret = timerManagerHandler_->ProxyTimer(uid1, pidList, true, true);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_[pid].size(), (const unsigned int)1);
    EXPECT_EQ(TimerProxy::GetInstance().IsPidProxy(pid, timerId1), true);
    EXPECT_EQ(TimerProxy::GetInstance().IsPidProxy(pid, timerId2), false);
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
    TimerProxy::GetInstance().pidTimersMap_.clear();
    TimerProxy::GetInstance().proxyPids_.clear();

    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {return 0;},
                                                    wantAgent, uid, pid, timerId, NOT_STORE);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    
    /* Start a timer. The timer can be started successfully and can be recorded in pidTimerMap_. */
    auto nowElapsed = timerManagerHandler_->GetBootTimeNs().time_since_epoch().count() / NANO_TO_MILESECOND;
    uint64_t triggerTime = 10000000 + nowElapsed;
    ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().pidTimersMap_.size(), (const unsigned int)1);

    /* The proxy of a timer is successful and can be recorded in proxyPid_. */
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyPids_.find(pid);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());
    EXPECT_EQ(it->second.size(), (const unsigned int)1);

    /* Cancel a proxy timer. The proxy is canceled successfully, and the proxyPid_ table is updated. */
    ret = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)0);

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
    bool retProxy = timerManagerHandler_->ProxyTimer(UID, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        EXPECT_EQ(TimerProxy::GetInstance().proxyUids_.size(), (const unsigned int) 1);
        auto it = TimerProxy::GetInstance().proxyUids_.find(UID);
        EXPECT_NE(it, TimerProxy::GetInstance().proxyUids_.end());
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

    TimerProxy::GetInstance().RemoveProxy(TIMER_ID, UID);
    TimerProxy::GetInstance().RemoveProxy(TIMER_ID + 1, UID);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        auto it = TimerProxy::GetInstance().proxyMap_.find(UID);
        EXPECT_EQ(it, TimerProxy::GetInstance().proxyMap_.end());
    }

    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    retProxy = timerManagerHandler_->ProxyTimer(UID, false, true);
    EXPECT_TRUE(retProxy);

    retProxy = timerManagerHandler_->ProxyTimer(UID, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);

    TimerProxy::GetInstance().ResetProxyMaps();

    TimerProxy::GetInstance().EraseTimerFromProxyUidMap(0, UID);
}


/**
* @tc.name: ProxyTimerCover003
* @tc.desc: test PID
* @tc.type: FUNC
*/
HWTEST_F(TimeProxyTest, ProxyTimerCover003, TestSize.Level1)
{
    TimerProxy::GetInstance().pidTimersMap_.clear();
    TimerProxy::GetInstance().proxyPids_.clear();
    int uid = 2000;
    std::set<int> pidList;
    pidList.insert(PID);
    bool retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    EXPECT_EQ(TimerProxy::GetInstance().proxyPids_.size(), (const unsigned int)1);
    auto it = TimerProxy::GetInstance().proxyPids_.find(PID);
    EXPECT_NE(it, TimerProxy::GetInstance().proxyPids_.end());

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, 0, PID, "");
    auto res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    auto timerInfo2 = std::make_shared<TimerInfo>("", TIMER_ID + 1, 0, duration, timePoint, duration, timePoint,
                                                  duration, nullptr, nullptr, 0, false, 0, PID, "");
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo2);
    EXPECT_EQ(res, E_TIME_OK);

    TimerProxy::GetInstance().RemovePidProxy(TIMER_ID, PID);
    TimerProxy::GetInstance().RemovePidProxy(TIMER_ID + 1, PID);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyPidMutex_);
        auto it = TimerProxy::GetInstance().proxyPidMap_.find(UID);
        EXPECT_EQ(it, TimerProxy::GetInstance().proxyPidMap_.end());
    }

    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);
    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, false, true);
    EXPECT_TRUE(retProxy);

    retProxy = timerManagerHandler_->ProxyTimer(uid, pidList, true, true);
    EXPECT_TRUE(retProxy);
    usleep(BLOCK_TEST_TIME);
    res = TimerProxy::GetInstance().CallbackAlarmIfNeed(timerInfo1);
    EXPECT_EQ(res, E_TIME_OK);

    TimerProxy::GetInstance().ResetProxyPidMaps();

    TimerProxy::GetInstance().EraseTimerFromProxyPidMap(0, PID);
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

    TimerProxy::GetInstance().RecordPidTimerMap(nullptr, false);
    TimerProxy::GetInstance().RemovePidTimerMap(nullptr);

    TimerProxy::GetInstance().RecordPidTimerMap(timerInfo, false);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().pidTimersMutex_);
        auto it = TimerProxy::GetInstance().pidTimersMap_.find(PID);
        EXPECT_NE(it, TimerProxy::GetInstance().pidTimersMap_.end());
    }
    TimerProxy::GetInstance().RemovePidTimerMap(timerInfo);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().pidTimersMutex_);
        auto it = TimerProxy::GetInstance().pidTimersMap_.find(PID);
        EXPECT_EQ(it, TimerProxy::GetInstance().pidTimersMap_.end());
    }
}

}  // MiscServices
}  // OHOS