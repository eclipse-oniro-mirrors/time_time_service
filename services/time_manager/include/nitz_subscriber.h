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

#ifndef NITZ_SUBSCRIBER_H
#define NITZ_SUBSCRIBER_H

#include <string>
#include <vector>
#include <map>

#include <common_event_publish_info.h>
#include "common_event.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::EventFwk;
class NITZSubscriber : public CommonEventSubscriber {
public:
    explicit NITZSubscriber(const CommonEventSubscribeInfo &subscriberInfo);
    ~NITZSubscriber() = default;
    virtual void OnReceiveEvent(const CommonEventData &data);

private:
    enum NITZBroadcastEventType {
        UNKNOWN_BROADCAST_EVENT = 0,
        NITZ_TIME_CHANGED_BROADCAST_EVENT,
        NITZ_TIMEZONE_CHANGED_BROADCAST_EVENT
    };
    using broadcastSubscriberFunc = void (NITZSubscriber::*)(const CommonEventData &data);

    void UnknownBroadcast(const CommonEventData &data);
    void NITZTimeChangeBroadcast(const CommonEventData &data);
    void NITZTimezoneChangeBroadcast(const CommonEventData &data);
    std::map<uint32_t, broadcastSubscriberFunc> memberFuncMap_;
};
} // MiscServices
} // OHOS
#endif // NITZ_SUBSCRIBER_H