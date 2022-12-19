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

#include "napi_system_time.h"

#include "napi_async_work.h"
#include "napi_utils.h"
#include "time_hilog_wreapper.h"
#include "time_service_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {
namespace Time {
napi_value NapiSystemTime::SystemTimeInit(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_STATIC_FUNCTION("setTime", SetTime),
        DECLARE_NAPI_STATIC_FUNCTION("getCurrentTime", GetCurrentTime),
        DECLARE_NAPI_STATIC_FUNCTION("getRealActiveTime", GetRealActiveTime),
        DECLARE_NAPI_STATIC_FUNCTION("getRealTime", GetRealTime),
        DECLARE_NAPI_STATIC_FUNCTION("setDate", SetDate),
        DECLARE_NAPI_STATIC_FUNCTION("getDate", GetDate),
        DECLARE_NAPI_STATIC_FUNCTION("setTimezone", SetTimezone),
        DECLARE_NAPI_STATIC_FUNCTION("getTimezone", GetTimezone),
    };

    napi_status status =
        napi_define_properties(env, exports, sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors);
    if (status != napi_ok) {
        TIME_HILOGE(TIME_MODULE_JS_NAPI, "define manager properties failed");
        return NapiUtils::GetUndefinedValue(env);
    }
    return exports;
}

napi_value NapiSystemTime::SetTime(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        context->status = napi_get_value_int64(env, argv[ARGV_FIRST], &context->time);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid time",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto ret = TimeServiceClient::GetInstance()->SetTime(context->time, context->errCode);
        if (!ret) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(context->errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "SetTime", executor, complete);
}

napi_value NapiSystemTime::SetDate(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        bool hasProperty = false;
        napi_valuetype resValueType = napi_undefined;
        napi_has_named_property(env, argv[ARGV_FIRST], "getTime", &hasProperty);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, hasProperty, "getTime failed", PARAMETER_ERROR);
        napi_value getTimeFunc = nullptr;
        napi_get_named_property(env, argv[0], "getTime", &getTimeFunc);
        napi_value getTimeResult = nullptr;
        napi_call_function(env, argv[0], getTimeFunc, 0, nullptr, &getTimeResult);
        napi_typeof(env, getTimeResult, &resValueType);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, resValueType == napi_number, "type mismatch",
            PARAMETER_ERROR);
        context->status = napi_get_value_int64(env, getTimeResult, &context->time);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid time",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto ret = TimeServiceClient::GetInstance()->SetTime(context->time, context->errCode);
        if (!ret) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(context->errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "SetTime", executor, complete);
}

napi_value NapiSystemTime::GetRealActiveTime(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
        bool isNano = true;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc <= ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        if (argc == ARGC_ONE) {
            context->status = napi_get_value_bool(env, argv[ARGV_FIRST], &context->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid isNano",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        if (context->isNano) {
            context->time = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
        } else {
            context->time = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
        }
        if (context->time < 0) {
            context->errMessage = SYSTEM_ERROR;
            context->errCode = ERROR;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = napi_create_int64(env, context->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetRealActiveTime", executor, complete);
}

napi_value NapiSystemTime::GetCurrentTime(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
        bool isNano = true;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc <= ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        if (argc == ARGC_ONE) {
            context->status = napi_get_value_bool(env, argv[ARGV_FIRST], &context->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid isNano",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        if (context->isNano) {
            context->time = TimeServiceClient::GetInstance()->GetWallTimeNs();
        } else {
            context->time = TimeServiceClient::GetInstance()->GetWallTimeMs();
        }
        if (context->time < 0) {
            context->errMessage = SYSTEM_ERROR;
            context->errCode = ERROR;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [context](napi_value &output) {
        context->status = napi_create_int64(context->env, context->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetCurrentTime", executor, complete);
}

napi_value NapiSystemTime::GetRealTime(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
        bool isNano = true;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc <= ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        if (argc == ARGC_ONE) {
            context->status = napi_get_value_bool(env, argv[ARGV_FIRST], &context->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid isNano",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        if (context->isNano) {
            context->time = TimeServiceClient::GetInstance()->GetBootTimeNs();
        } else {
            context->time = TimeServiceClient::GetInstance()->GetBootTimeMs();
        }
        if (context->time < 0) {
            context->errMessage = SYSTEM_ERROR;
            context->errCode = ERROR;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [context](napi_value &output) {
        context->status = napi_create_int64(context->env, context->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetRealTime", executor, complete);
}

napi_value NapiSystemTime::GetDate(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        int64_t time;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        context->time = TimeServiceClient::GetInstance()->GetWallTimeMs();
        if (context->time < 0) {
            context->errMessage = SYSTEM_ERROR;
            context->errCode = ERROR;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = napi_create_date(env, context->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetDate", executor, complete);
}

napi_value NapiSystemTime::SetTimezone(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::string timezone;
    };
    auto context = std::make_shared<ConcreteContext>();

    auto inputParser = [env, context](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, argc == ARGC_ONE, "invalid arguments", PARAMETER_ERROR);
        context->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], context->timezone);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, context->status == napi_ok, "invalid timezone",
            PARAMETER_ERROR);
        context->status = napi_ok;
    };
    context->GetCbInfo(env, info, inputParser);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        auto ret = TimeServiceClient::GetInstance()->SetTimeZone(context->timezone, context->errCode);
        if (!ret) {
            JsErrorInfo errorObject = NapiUtils::ConvertErrorCode(context->errCode);
            context->errMessage = errorObject.message.c_str();
            context->errCode = errorObject.code;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };

    return NapiAsyncWork::Enqueue(env, context, "SetTimezone", executor, complete);
}

napi_value NapiSystemTime::GetTimezone(napi_env env, napi_callback_info info)
{
    struct ConcreteContext : public ContextBase {
        std::string timezone;
    };
    auto context = std::make_shared<ConcreteContext>();
    context->GetCbInfo(env, info);
    if (context->status != napi_ok) {
        NapiUtils::ThrowError(env, context->errMessage.c_str(), context->errCode);
        return NapiUtils::GetUndefinedValue(env);
    }

    auto executor = [context]() {
        context->timezone = TimeServiceClient::GetInstance()->GetTimeZone();

        if (context->timezone.empty()) {
            context->errMessage = SYSTEM_ERROR;
            context->errCode = ERROR;
            context->status = napi_generic_failure;
        }
    };

    auto complete = [env, context](napi_value &output) {
        context->status = napi_create_string_utf8(env, context->timezone.c_str(), context->timezone.size(), &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, context, "convert native object to javascript object failed",
            ERROR);
    };

    return NapiAsyncWork::Enqueue(env, context, "GetTimezone", executor, complete);
}
} // namespace Time
} // namespace MiscServices
} // namespace OHOS