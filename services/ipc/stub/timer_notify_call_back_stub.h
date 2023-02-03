/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef TIMER_NOTIFY_CALL_BACK_STUB_H
#define TIMER_NOTIFY_CALL_BACK_STUB_H

#include <cinttypes>
#include <iremote_stub.h>
#include <nocopyable.h>

#include "itimer_notify_call_back.h"
#include "time_common.h"

namespace OHOS {
namespace MiscServices {
class TimerNotifyCallbackStub : public IRemoteStub<ITimerNotifyCallback> {
public:
    DISALLOW_COPY_AND_MOVE(TimerNotifyCallbackStub);
    TimerNotifyCallbackStub() = default;
    virtual ~TimerNotifyCallbackStub() = default;
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
	
private:
    int OnFinishStub(MessageParcel& data);
};
} // namespace MiscServices
} // namespace OHOS

#endif // TIMER_NOTIFY_CALL_BACK_STUB_H