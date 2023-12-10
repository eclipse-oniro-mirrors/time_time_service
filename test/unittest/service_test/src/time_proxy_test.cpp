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

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace std::chrono;

namespace {
constexpr uint64_t NANO_TO_MILESECOND = 100000;
constexpr int BLOCK_TEST_TIME = 100000;
}
std::shared_ptr<TimerManager> timerManagerHandler_ = nullptr;

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
    timerManagerHandler_ = TimerManager::Create();
    EXPECT_NE(timerManagerHandler_, nullptr);
    TIME_HILOGI(TIME_MODULE_SERVICE, "end SetUp.");
    usleep(BLOCK_TEST_TIME);
}

void TimeProxyTest::TearDown(void)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "start TearDown.");
    timerManagerHandler_->alarmThread_->detach();
    timerManagerHandler_ = nullptr;
    EXPECT_EQ(timerManagerHandler_, nullptr);
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
    uint64_t timerId = 1000;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {}, wantAgent, uid, timerId);
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
    uint64_t timerId = 1000;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {}, wantAgent, uid, timerId);
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
    uint64_t timerId = 1000;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {}, wantAgent, uid, timerId);
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
    uint64_t timerId = 1000;
    int32_t ret = timerManagerHandler_->CreateTimer(paras, [] (const uint64_t) {}, wantAgent, uid, timerId);
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
}  // MiscServices
}  // OHOS