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

using namespace taihe;
using namespace ohos::time_service::systemtimer;
using namespace OHOS::MiscServices;
using namespace OHOS::MiscServices::Time;

namespace {
// To be implemented.

int64_t CreateTimerSync(::ohos::time_service::systemtimer::TimerOptions const& options)
{
    std::shared_ptr<ITimerInfoInstance> iTimerInfoInstance = std::make_shared<ITimerInfoInstance>();
    iTimerInfoInstance->SetType(options.type);
    iTimerInfoInstance->SetRepeat(options.repeat);
    int64_t intervalValue = options.interval.value_or(0);
    iTimerInfoInstance->SetInterval(intervalValue);
    std::string nameValue = std::string(options.name.value_or(""));
    iTimerInfoInstance->SetName(nameValue);
    auto callback = options.callback;
    if (callback.has_value()) {
        iTimerInfoInstance->SetCallbackInfo(std::function<void()>(callback.value()));
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
}  // namespace

TH_EXPORT_CPP_API_CreateTimerSync(CreateTimerSync);
TH_EXPORT_CPP_API_StartTimerSync(StartTimerSync);
TH_EXPORT_CPP_API_StopTimerSync(StopTimerSync);
TH_EXPORT_CPP_API_DestroyTimerSync(DestroyTimerSync);