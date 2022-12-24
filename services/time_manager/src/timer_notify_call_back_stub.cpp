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

#include "timer_notify_call_back_stub.h"

namespace OHOS {
namespace MiscServices {
int TimerNotifyCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "cmd = %{public}d, flags = %{public}d", code, option.GetFlags());
    std::u16string descripter = GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed,descripter is not matched!");
        return E_TIME_READ_PARCEL_ERROR;
    }
	
    switch (code) {
        case static_cast<int>(ITimerNotifyCallback::Message::FINISH): {
            return OnFinishStub(data);
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_OK;
}

int TimerNotifyCallbackStub::OnFinishStub(MessageParcel& data)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    auto timerId = data.ReadUint64();
    TIME_HILOGD(TIME_MODULE_SERVICE, "id: %{public}" PRId64 "", timerId);
    Finish(timerId);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}
} // namespace MiscServices
} // namespace OHOS