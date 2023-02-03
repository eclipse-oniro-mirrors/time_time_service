/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "nitz_subscriber.h"
#include "time_common.h"
#include "ntp_update_time.h"
namespace OHOS {
namespace MiscServices {
using namespace OHOS::EventFwk;
using namespace OHOS::AAFwk;
NITZSubscriber::NITZSubscriber(
    const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    memberFuncMap_[UNKNOWN_BROADCAST_EVENT] = &NITZSubscriber::UnknownBroadcast;
    memberFuncMap_[NITZ_TIME_CHANGED_BROADCAST_EVENT] = &NITZSubscriber::NITZTimeChangeBroadcast;
    memberFuncMap_[NITZ_TIMEZONE_CHANGED_BROADCAST_EVENT] = &NITZSubscriber::NITZTimezoneChangeBroadcast;
}

void NITZSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    uint32_t code = UNKNOWN_BROADCAST_EVENT;
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = data.GetWant().GetAction();
    TIME_HILOGD(TIME_MODULE_SERVICE, "receive one broadcast:%{public}s", action.c_str());

    if (action == CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED) {
        code = NITZ_TIME_CHANGED_BROADCAST_EVENT;
    } else {
        code = UNKNOWN_BROADCAST_EVENT;
    }

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data);
        }
    }
}

void NITZSubscriber::UnknownBroadcast(const CommonEventData &data)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "you receive one unknown broadcast!");
}

void NITZSubscriber::NITZTimeChangeBroadcast(const CommonEventData &data)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "NITZ Timezone changed broadcast code:%{public}d", data.GetCode());
    DelayedSingleton<NtpUpdateTime>::GetInstance()->UpdateNITZSetTime();
}

void NITZSubscriber::NITZTimezoneChangeBroadcast(const CommonEventData &data)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "NITZ Time changed broadcast code:%{public}d", data.GetCode());
}
} // MiscServices
} // OHOS