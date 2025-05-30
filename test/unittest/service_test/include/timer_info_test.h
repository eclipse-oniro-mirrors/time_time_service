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
#ifndef OHOS_GLOBAL_TIME_SERVICE_TEST_H
#define OHOS_GLOBAL_TIME_SERVICE_TEST_H

#include <cstdint>
#include <functional>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <string>
#include <sys/time.h>
#include <thread>
#include <vector>

#include "time_common.h"

#define private public
#include "time_service_client.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr uint64_t NANO_TO_MILESECOND = 1000000;
constexpr uint64_t NANO_TO_SECOND = 1000000000;
}
class TimerInfoTest : public ITimerInfo {
public:
    TimerInfoTest();
    virtual ~TimerInfoTest();
    virtual void OnTrigger() override;
    virtual void SetType(const int &type) override;
    virtual void SetRepeat(bool repeat) override;
    virtual void SetInterval(const uint64_t &interval) override;
    void SetDisposable(const bool &disposable);
    virtual void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override;
    void SetCallbackInfo(const std::function<void()> &callBack);

private:
    std::function<void()> callBack_ = nullptr;
};

TimerInfoTest::TimerInfoTest()
{
}

TimerInfoTest::~TimerInfoTest()
{
}

void TimerInfoTest::OnTrigger()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (callBack_ != nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "call back.");
        callBack_();
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
}

void TimerInfoTest::SetCallbackInfo(const std::function<void()> &callBack)
{
    callBack_ = callBack;
}

void TimerInfoTest::SetType(const int &_type)
{
    type = _type;
}

void TimerInfoTest::SetRepeat(bool _repeat)
{
    repeat = _repeat;
}

void TimerInfoTest::SetInterval(const uint64_t &_interval)
{
    interval = _interval;
}

void TimerInfoTest::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent)
{
    wantAgent = _wantAgent;
}

void TimerInfoTest::SetDisposable(const bool &_disposable)
{
    disposable = _disposable;
}

} // namespace MiscServices
} // namespace OHOS
#endif