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

#include "napi_system_timer.h"

#include <uv.h>

#include "napi_utils.h"
#include "securec.h"
#include "time_hilog_wreapper.h"
#include "timer_type.h"

namespace OHOS {
namespace MiscServices {
namespace Time {
struct ReceiveDataWorker {
    napi_env env = nullptr;
    napi_ref ref = 0;
};
ITimerInfoInstance::ITimerInfoInstance() : callbackInfo_{}
{
}

ITimerInfoInstance::~ITimerInfoInstance()
{
}

void ITimerInfoInstance::OnTrigger()
{
    if (callbackInfo_.ref == nullptr) {
        return;
    }

    uv_loop_s *loop = nullptr;
#if NAPI_VERSION >= 2
    napi_get_uv_event_loop(callbackInfo_.env, &loop);
#endif // NAPI_VERSION >= 2

    ReceiveDataWorker *dataWorker = new (std::nothrow) ReceiveDataWorker();
    if (!dataWorker) {
        return;
    }
    dataWorker->env = callbackInfo_.env;
    dataWorker->ref = callbackInfo_.ref;

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (!work) {
        delete dataWorker;
        return;
    }
    if (!loop) {
        delete dataWorker;
        delete work;
        return;
    }
    work->data = (void *)dataWorker;
    uv_queue_work(
        loop, work, [](uv_work_t *work) {},
        [](uv_work_t *work, int status) {
            ReceiveDataWorker *dataWorkerData = (ReceiveDataWorker *)work->data;
            if (dataWorkerData == nullptr) {
                return;
            }

            NapiUtils::SetCallback(dataWorkerData->env, dataWorkerData->ref, ERROR_OK, "",
                NapiUtils::GetUndefinedValue(dataWorkerData->env));
            delete dataWorkerData;
            dataWorkerData = nullptr;
            delete work;
            work = nullptr;
        });
}

void ITimerInfoInstance::SetCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    callbackInfo_.env = env;
    callbackInfo_.ref = ref;
}

void ITimerInfoInstance::SetType(const int &_type)
{
    type = _type;
}

void ITimerInfoInstance::SetRepeat(bool _repeat)
{
    repeat = _repeat;
}
void ITimerInfoInstance::SetInterval(const uint64_t &_interval)
{
    interval = _interval;
}
void ITimerInfoInstance::SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent)
{
    wantAgent = _wantAgent;
}

napi_value NapiSystemTimer::SystemTimerInit(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createTimer", CreateTimer),
        DECLARE_NAPI_STATIC_FUNCTION("startTimer", StartTimer),
        DECLARE_NAPI_STATIC_FUNCTION("stopTimer", StopTimer),
        DECLARE_NAPI_STATIC_FUNCTION("destroyTimer", DestroyTimer),
        DECLARE_NAPI_PROPERTY("TIMER_TYPE_REALTIME", NapiUtils::CreateNapiNumber(env, 1 << TIMER_TYPE_REALTIME)),
        DECLARE_NAPI_PROPERTY("TIMER_TYPE_WAKEUP", NapiUtils::CreateNapiNumber(env, 1 << TIMER_TYPE_WAKEUP)),
        DECLARE_NAPI_PROPERTY("TIMER_TYPE_EXACT", NapiUtils::CreateNapiNumber(env, 1 << TIMER_TYPE_EXACT)),
        DECLARE_NAPI_PROPERTY("TIMER_TYPE_IDLE", NapiUtils::CreateNapiNumber(env, 1 << TIMER_TYPE_IDLE)),
    };

    napi_status status =
        napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);
    if (status != napi_ok) {
        TIME_HILOGE(TIME_MODULE_JS_NAPI, "define manager properties failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    return exports;
}

void NapiSystemTimer::GetTimerOptions(const napi_env &env, std::shared_ptr<ContextBase> context,
    const napi_value &value, std::shared_ptr<ITimerInfoInstance> &iTimerInfoInstance)
{
    napi_valuetype valueType = napi_undefined;
    napi_value result = nullptr;
    OHOS::AbilityRuntime::WantAgent::WantAgent *wantAgent = nullptr;
    bool hasProperty = false;

    // type: number
    int type = 0;
    napi_has_named_property(env, value, "type", &hasProperty);
    CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, hasProperty, "type expected.", PARAMETER_ERROR);
    napi_get_named_property(env, value, "type", &result);
    napi_typeof(env, result, &valueType);
    CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, valueType == napi_number,
        "Parameter error. The type of type must be number.", PARAMETER_ERROR);
    napi_get_value_int32(env, result, &type);
    iTimerInfoInstance->SetType(type);

    // repeat: boolean
    bool repeat = false;
    napi_has_named_property(env, value, "repeat", &hasProperty);
    CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, hasProperty, "repeat expected.", PARAMETER_ERROR);
    napi_get_named_property(env, value, "repeat", &result);
    napi_typeof(env, result, &valueType);
    CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, valueType == napi_boolean,
        "Parameter error. The type of repeat must be boolean.", PARAMETER_ERROR);
    napi_get_value_bool(env, result, &repeat);
    iTimerInfoInstance->SetRepeat(repeat);

    // interval?: number
    int64_t interval = 0;
    napi_has_named_property(env, value, "interval", &hasProperty);
    if (hasProperty) {
        napi_get_named_property(env, value, "interval", &result);
        napi_typeof(env, result, &valueType);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, valueType == napi_number,
            "Parameter error. The type of interval must be number.", PARAMETER_ERROR);
        napi_get_value_int64(env, result, &interval);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, interval >= 0,
            "Wrong argument number. Positive number expected.", PARAMETER_ERROR);
        iTimerInfoInstance->SetInterval((uint64_t)interval);
    }

    // wantAgent?: WantAgent
    napi_has_named_property(env, value, "wantAgent", &hasProperty);
    if (hasProperty) {
        napi_get_named_property(env, value, "wantAgent", &result);
        napi_typeof(env, result, &valueType);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, valueType == napi_object,
            "Parameter error. The type of wantAgent must be WantAgent.", PARAMETER_ERROR);
        napi_unwrap(env, result, (void **)&wantAgent);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, wantAgent != nullptr, "wantAgent is nullptr.",
            PARAMETER_ERROR);
        std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> sWantAgent =
            std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>(*wantAgent);
        iTimerInfoInstance->SetWantAgent(sWantAgent);
    }

    // callback?: () => void
    napi_has_named_property(env, value, "callback", &hasProperty);
    if (hasProperty) {
        napi_get_named_property(env, value, "callback", &result);
        napi_typeof(env, result, &valueType);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, valueType == napi_function,
            "Parameter error. The type of callback must be function.", PARAMETER_ERROR);
        napi_ref onTriggerCallback;
        napi_create_reference(env, result, 1, &onTriggerCallback);
        iTimerInfoInstance->SetCallbackInfo(env, onTriggerCallback);
    }
}

napi_value NapiSystemTimer::CreateTimer(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        uint64_t timerId;
        std::shared_ptr<ITimerInfoInstance> iTimerInfoInstance = std::make_shared<ITimerInfoInstance>();
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        GetTimerOptions(env, context, argv[ARGV_FIRST], context->iTimerInfoInstance);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid timer",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto errCode = OHOS::MiscServices::TimeServiceClient::GetInstance()->CreateTimerV9(context->iTimerInfoInstance,
            context->timerId);
        if (errCode != ERROR_OK) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [context](napi_value &output) {
        uint64_t timerId = static_cast<uint64_t>(context->timerId);
        context->status = napi_create_int64(context->env, timerId, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "SetTime", executor, complete);
}

napi_value NapiSystemTimer::StartTimer(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        uint64_t timerId;
        uint64_t triggerTime;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_TWO, "invalid arguments", PARAMETER_ERROR);
        int64_t timerId = 0;
        context->status = napi_get_value_int64(env, argv[ARGV_FIRST], &timerId);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid timerId",
            PARAMETER_ERROR);
        context->timerId = static_cast<uint64_t>(timerId);
        int64_t triggerTime = 0;
        context->status = napi_get_value_int64(env, argv[ARGV_SECOND], &triggerTime);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid triggerTime",
            PARAMETER_ERROR);
        context->triggerTime = static_cast<uint64_t>(triggerTime);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto errCode =
            OHOS::MiscServices::TimeServiceClient::GetInstance()->StartTimerV9(context->timerId, context->triggerTime);
        if (errCode != ERROR_OK) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StartTimer", executor, complete);
}

napi_value NapiSystemTimer::StopTimer(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        uint64_t timerId;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        int64_t timerId = 0;
        context->status = napi_get_value_int64(env, argv[ARGV_FIRST], &timerId);
        context->timerId = static_cast<uint64_t>(timerId);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid timerId",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto errCode = TimeServiceClient::GetInstance()->StopTimerV9(context->timerId);
        if (errCode != ERROR_OK) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "StopTimer", executor, complete);
}

napi_value NapiSystemTimer::DestroyTimer(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        uint64_t timerId;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        int64_t timerId = 0;
        context->status = napi_get_value_int64(env, argv[ARGV_FIRST], &timerId);
        context->timerId = static_cast<uint64_t>(timerId);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid timerId",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(context->timerId);
        if (errCode != ERROR_OK) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "DestroyTimer", executor, complete);
}
} // namespace Time
} // namespace MiscServices
} // namespace OHOS