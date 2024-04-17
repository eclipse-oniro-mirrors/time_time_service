/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "user_switch_subscriber.h"
#include "time_system_ability.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::EventFwk;
using namespace OHOS::AAFwk;
UserSwitchSubscriber::UserSwitchSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    memberFuncMap_[USER_SWITCH_BROADCAST_EVENT] = &UserSwitchSubscriber::UserSwitchBroadcast;
}

void UserSwitchSubscriber::OnReceiveEvent(const CommonEventData &data)
{
    uint32_t code = UNKNOWN_BROADCAST_EVENT;
    OHOS::EventFwk::Want want = data.GetWant();
    std::string action = data.GetWant().GetAction();
    TIME_HILOGD(TIME_MODULE_SERVICE, "receive one broadcast:%{public}s", action.c_str());
    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        code = USER_SWITCH_BROADCAST_EVENT;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data);
        }
    }
}

void UserSwitchSubscriber::UserSwitchBroadcast(const CommonEventData &data)
{
    TimeSystemAbility::GetInstance()->Recover();
}
} // namespace MiscServices
} // namespace OHOS