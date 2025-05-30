/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef TIMER_CALL_BACK_H
#define TIMER_CALL_BACK_H

#include "itimer_info.h"
#include "time_common.h"
#include "timer_callback_stub.h"

namespace OHOS {
namespace MiscServices {
class TimerCallback : public TimerCallbackStub {
public:
    DISALLOW_COPY_AND_MOVE(TimerCallback);
    static sptr<TimerCallback> GetInstance();
    virtual int32_t NotifyTimer(uint64_t timerId) override;
    /**
     * Get timer callback info.
     *
     * @param  timerInfo the timer info
     * @param  timerInfo  the timer info
     * @return Get timer callback info success or not
     */
    bool InsertTimerCallbackInfo(uint64_t timerId, const std::shared_ptr<ITimerInfo> &timerInfo);
    bool RemoveTimerCallbackInfo(uint64_t timerId);

private:
    TimerCallback();
    ~TimerCallback();

    static std::mutex instanceLock_;
    static sptr<TimerCallback> instance_;
    std::map<uint64_t, std::shared_ptr<ITimerInfo>> timerInfoMap_;
    std::mutex timerInfoMutex_;
};
} // namespace MiscServices
} // namespace OHOS

#endif // TIMER_CALL_BACK_H