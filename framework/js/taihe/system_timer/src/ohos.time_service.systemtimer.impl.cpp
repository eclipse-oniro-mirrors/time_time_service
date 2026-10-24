/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ohos.time_service.systemtimer.proj.hpp"
#include "ohos.time_service.systemtimer.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "ani_system_timer.h"
#include "ani_utils.h"
#include "time_common.h"
#include "time_hilog.h"
#include "ani_common_want_agent.h"

using namespace taihe;
using namespace ohos::time_service::systemtimer;
using namespace OHOS::MiscServices;
using namespace OHOS::MiscServices::Time;
using namespace OHOS;

namespace {
// To be implemented.

// Max UTF-8 bytes of the timer name (aligned with NAPI STR_MAX_LENGTH=64).
constexpr size_t MAX_TIMER_NAME_BYTES = 64;

ani_status GetWantAgent(ani_env *env, const ani_object &value,
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &wantAgent)
{
    AbilityRuntime::WantAgent::WantAgent *wantAgentPtr = nullptr;
    AppExecFwk::UnwrapWantAgent(env, value, reinterpret_cast<void **>(&wantAgentPtr));
    if (wantAgentPtr == nullptr) {
        TIME_HILOGI(TIME_MODULE_JS_NAPI, "wantAgentPtr is nullptr");
        return ANI_ERROR;
    }
    wantAgent = std::make_shared<AbilityRuntime::WantAgent::WantAgent>(*wantAgentPtr);
    return ANI_OK;
}

int64_t CreateTimerSync(::ohos::time_service::systemtimer::TimerOptions const& options)
{
    std::shared_ptr<ITimerInfoInstance> iTimerInfoInstance = std::make_shared<ITimerInfoInstance>();
    iTimerInfoInstance->SetType(options.type);
    iTimerInfoInstance->SetRepeat(options.repeat);
    int64_t intervalValue = options.interval.value_or(0);
    iTimerInfoInstance->SetInterval(intervalValue);
    std::string nameValue = std::string(options.name.value_or(""));
    iTimerInfoInstance->SetName(nameValue);
    bool autoRestoreValue = options.autoRestore.value_or(false);
    iTimerInfoInstance->SetAutoRestore(autoRestoreValue);
    auto callback = options.callback;
    if (callback.has_value()) {
        iTimerInfoInstance->SetCallbackInfo(std::function<void()>(callback.value()));
    }
    auto wantAgent = options.wantAgent;
    if (wantAgent.has_value()) {
        auto env = taihe::get_env();
        std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgentPtr =
            std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>();
        if (GetWantAgent(env, reinterpret_cast<ani_object>(wantAgent.value()), wantAgentPtr) == ANI_OK) {
            iTimerInfoInstance->SetWantAgent(wantAgentPtr);
        }
    }
    uint64_t timerId = 0;
    auto innerCode = TimeServiceClient::GetInstance()->CreateTimerV9(iTimerInfoInstance, timerId);
    if (innerCode != JsErrorCode::ERROR_OK) {
        int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
        std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
        set_business_error(errorCode, errorMessage);
        return 0;
    }
    return timerId;
}

void StartTimerSync(int64_t timer, int64_t triggerTime)
{
    auto innerCode = TimeServiceClient::GetInstance()->StartTimerV9(timer, triggerTime);
    if (innerCode != JsErrorCode::ERROR_OK) {
        int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
        std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
        set_business_error(errorCode, errorMessage);
        return;
    }
}

void StopTimerSync(int64_t timer)
{
    auto innerCode = TimeServiceClient::GetInstance()->StopTimerV9(timer);
    if (innerCode != JsErrorCode::ERROR_OK) {
        int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
        std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
        set_business_error(errorCode, errorMessage);
        return;
    }
}

void DestroyTimerSync(int64_t timer)
{
    auto innerCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timer);
    if (innerCode != JsErrorCode::ERROR_OK) {
        int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
        std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
        set_business_error(errorCode, errorMessage);
        return;
    }
}

void SetPowerOnTimerEnabledSync(optional_view<PowerOnTimerEnabledOptions> const& options)
{
    // options omitted: enable all power-on timers (spec).
    if (!options.has_value()) {
        int32_t innerCode = TimeServiceClient::GetInstance()->SetPowerOnTimerEnabled("", true);
        if (innerCode != JsErrorCode::ERROR_OK) {
            int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
            std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
            set_business_error(errorCode, errorMessage);
        }
        return;
    }
    auto const& opts = options.value();
    // timerName optional: when omitted, the operation applies to all power-on
    // timers (timerName stays empty). An explicit empty or over-64-byte string
    // is rejected.
    std::string timerName;
    if (opts.timerName.has_value()) {
        timerName = std::string(opts.timerName.value());
        if (timerName.empty() || timerName.size() > MAX_TIMER_NAME_BYTES) {
            set_business_error(AniUtils::ConvertErrorCode(E_TIME_PARAMETERS_INVALID), "Invalid timer name");
            return;
        }
    }
    // enable is optional, defaults to true (enable).
    bool enable = opts.enable.value_or(true);
    int32_t innerCode = TimeServiceClient::GetInstance()->SetPowerOnTimerEnabled(timerName, enable);
    TIME_HILOGI(TIME_MODULE_JS_ANI, "Taihe SetPowerOnTimerEnabled name:%{public}s enable:%{public}d ret:%{public}d",
        timerName.c_str(), enable, innerCode);
    if (innerCode != JsErrorCode::ERROR_OK) {
        int32_t errorCode = AniUtils::ConvertErrorCode(innerCode);
        std::string errorMessage = AniUtils::GetErrorMessage(errorCode);
        set_business_error(errorCode, errorMessage);
        return;
    }
}
}  // namespace

TH_EXPORT_CPP_API_CreateTimerAsync(CreateTimerSync);
TH_EXPORT_CPP_API_CreateTimerPromise(CreateTimerSync);
TH_EXPORT_CPP_API_CreateTimerSync(CreateTimerSync);
TH_EXPORT_CPP_API_StartTimerAsync(StartTimerSync);
TH_EXPORT_CPP_API_StartTimerPromise(StartTimerSync);
TH_EXPORT_CPP_API_StartTimerSync(StartTimerSync);
TH_EXPORT_CPP_API_StopTimerAsync(StopTimerSync);
TH_EXPORT_CPP_API_StopTimerPromise(StopTimerSync);
TH_EXPORT_CPP_API_StopTimerSync(StopTimerSync);
TH_EXPORT_CPP_API_DestroyTimerAsync(DestroyTimerSync);
TH_EXPORT_CPP_API_DestroyTimerPromise(DestroyTimerSync);
TH_EXPORT_CPP_API_DestroyTimerSync(DestroyTimerSync);
TH_EXPORT_CPP_API_SetPowerOnTimerEnabledPromise(SetPowerOnTimerEnabledSync);
TH_EXPORT_CPP_API_SetPowerOnTimerEnabledSync(SetPowerOnTimerEnabledSync);