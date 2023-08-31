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

#include "time_service_fuzz_utils.h"

#include "message_parcel.h"
#include "time_common.h"
#include "time_system_ability.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr int32_t DELAY_TIME = 3000;
const std::u16string TIMESERVICE_INTERFACE_TOKEN = u"ohos.miscservices.time.ITimeService";

void TimeServiceFuzzUtils::OnRemoteRequestTest(uint32_t code, const uint8_t *rawData, size_t size)
{
    MessageParcel data;
    data.WriteInterfaceToken(TIMESERVICE_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    TimeSystemAbility::GetInstance()->OnRemoteRequest(code, data, reply, option);
}

void TimeServiceFuzzUtils::SetTimer()
{
    TimerPara timerPara{ 0, 0, 0, 0 };
    uint64_t timerId = 0;
    TimeSystemAbility::GetInstance()->CreateTimer(
        timerPara, [](uint64_t id) {}, timerId);
    int64_t triggerTime = 0;
    TimeSystemAbility::GetInstance()->GetWallTimeMs(triggerTime);
    TimeSystemAbility::GetInstance()->StartTimer(timerId, triggerTime + DELAY_TIME);
}
} // namespace OHOS