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

#ifndef TIME_TICK_NOTIFY_H
#define TIME_TICK_NOTIFY_H

#include "timer.h"

namespace OHOS {
namespace MiscServices {
class TimeTickNotify {
public:
    static TimeTickNotify &GetInstance();
    TimeTickNotify();
    ~TimeTickNotify();
    void Init();
    void Callback();
    void Stop();
    void PowerCallback();

private:
    uint64_t RefreshNextTriggerTime();
    Utils::Timer timer_;
    uint32_t timerId_;
};
} // namespace MiscServices
} // namespace OHOS
#endif