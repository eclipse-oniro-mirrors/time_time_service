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

#ifndef NAPI_SYSTEM_TIMER_H
#define NAPI_SYSTEM_TIMER_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_async_work.h"
#include "time_service_client.h"

namespace OHOS {
namespace MiscServices {
namespace Time {
class ITimerInfoInstance : public OHOS::MiscServices::ITimerInfo {
public:
    ITimerInfoInstance();
    virtual ~ITimerInfoInstance();
    virtual void OnTrigger() override;
    virtual void SetType(const int &type) override;
    virtual void SetRepeat(bool repeat) override;
    virtual void SetInterval(const uint64_t &interval) override;
    virtual void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override;
    void SetCallbackInfo(const napi_env &env, const napi_ref &ref);

private:
    struct CallbackInfo {
        napi_env env;
        napi_ref ref;
    };

    CallbackInfo callbackInfo_;
};

class NapiSystemTimer {
public:
    static napi_value SystemTimerInit(napi_env env, napi_value exports);
    static void GetTimerOptions(const napi_env &env, ContextBase *context, const napi_value &value,
                                std::shared_ptr<ITimerInfoInstance> &iTimerInfoInstance);
    static napi_value CreateTimer(napi_env env, napi_callback_info info);
    static napi_value StartTimer(napi_env env, napi_callback_info info);
    static napi_value StopTimer(napi_env env, napi_callback_info info);
    static napi_value DestroyTimer(napi_env env, napi_callback_info info);
};

}
}
}
#endif // NAPI_SYSTEM_TIMER_H