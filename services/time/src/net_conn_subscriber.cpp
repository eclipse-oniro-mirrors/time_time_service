/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "net_conn_subscriber.h"
#include "ntp_update_time.h"
#include "time_common.h"
#include "time_tick_notify.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::EventFwk;
using namespace OHOS::AAFwk;
NetConnSubscriber::NetConnSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    memberFuncMap_ = {
        { CONNECTED, [this] (const CommonEventData &data) { NetConnStateConnected(data); } },
    };
}

void NetConnSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    uint32_t code = UNKNOWN_BROADCAST_EVENT;
    std::string action = data.GetWant().GetAction();
    TIME_HILOGD(TIME_MODULE_SERVICE, "receive one broadcast:%{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_CONNECTIVITY_CHANGE) {
        code = data.GetCode();
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return memberFunc(data);
        }
    }
}

void NetConnSubscriber::NetConnStateConnected(const CommonEventData &data)
{
    if (NtpUpdateTime::GetInstance().IsValidNITZTime()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "NITZ Time is valid.");
        return;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Internet ready");
    NtpUpdateTime::SetSystemTime();
}
} // namespace MiscServices
} // namespace OHOS