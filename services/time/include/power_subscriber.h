/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef POWER_SUBSCRIBER_H
#define POWER_SUBSCRIBER_H

#include <common_event_publish_info.h>
#include <map>
#include <string>
#include <vector>

#include "common_event.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::EventFwk;
class PowerSubscriber : public CommonEventSubscriber {
public:
    explicit PowerSubscriber(const CommonEventSubscribeInfo &subscriberInfo);
    ~PowerSubscriber() = default;
    virtual void OnReceiveEvent(const CommonEventData &data);

private:
    enum PowerBroadcastEventType {
        UNKNOWN_BROADCAST_EVENT = 0,
        POWER_BROADCAST_EVENT,
    };
    using broadcastSubscriberFunc = void (PowerSubscriber::*)(const CommonEventData &data);

    void UnknownBroadcast(const CommonEventData &data);
    void PowerBroadcast(const CommonEventData &data);
    std::map<uint32_t, broadcastSubscriberFunc> memberFuncMap_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // POWER_SUBSCRIBER_H