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

#include "napi_system_date_time.h"

#include "napi_async_work.h"
#include "napi_utils.h"
#include "time_hilog_wreapper.h"
#include "time_service_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {
namespace Time {
napi_value NapiSystemDateTime::SystemDateTimeInit(napi_env env, napi_value exports)
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

napi_value NapiSystemDateTime::SetTime(napi_env env, napi_callback_info info)
{
    struct SetTimeContext : public ContextBase {
        int64_t time = 0;
    };
    SetTimeContext *setTimeContext = new SetTimeContext();
    auto inputParser = [env, setTimeContext](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setTimeContext, argc >= ARGC_ONE, "invalid arguments",
            JsErrorCode::PARAMETER_ERROR);
        setTimeContext->status = napi_get_value_int64(env, argv[ARGV_FIRST], &setTimeContext->time);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setTimeContext, setTimeContext->status == napi_ok, "invalid time",
            JsErrorCode::PARAMETER_ERROR);
        setTimeContext->status = napi_ok;
    };
    setTimeContext->GetCbInfo(env, info, inputParser);
    auto executor = [setTimeContext]() {
        auto innerCode = TimeServiceClient::GetInstance()->SetTimeV9(setTimeContext->time);
        if (innerCode != JsErrorCode::ERROR_OK) {
            setTimeContext->errCode = innerCode;
            setTimeContext->status = napi_generic_failure;
        }
    };
    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, setTimeContext, "SetTime", executor, complete);
}

napi_value NapiSystemDateTime::SetDate(napi_env env, napi_callback_info info)
{
    struct SetDateContext : public ContextBase {
        int64_t time = 0;
    };
    SetDateContext *setDateContext = new SetDateContext();
    auto inputParser = [env, setDateContext](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setDateContext, argc >= ARGC_ONE, "invalid arguments",
            JsErrorCode::PARAMETER_ERROR);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[ARGV_FIRST], &valueType);
        if (valueType == napi_number) {
            napi_get_value_int64(env, argv[ARGV_FIRST], &setDateContext->time);
            CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setDateContext, setDateContext->time >= 0, "invalid time",
                JsErrorCode::PARAMETER_ERROR);
        } else {
            bool hasProperty = false;
            napi_valuetype resValueType = napi_undefined;
            napi_has_named_property(env, argv[ARGV_FIRST], "getTime", &hasProperty);
            CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setDateContext, hasProperty, "getTime failed",
                JsErrorCode::PARAMETER_ERROR);
            napi_value getTimeFunc = nullptr;
            napi_get_named_property(env, argv[0], "getTime", &getTimeFunc);
            napi_value getTimeResult = nullptr;
            napi_call_function(env, argv[0], getTimeFunc, 0, nullptr, &getTimeResult);
            napi_typeof(env, getTimeResult, &resValueType);
            CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setDateContext, resValueType == napi_number, "type mismatch",
                JsErrorCode::PARAMETER_ERROR);
            setDateContext->status = napi_get_value_int64(env, getTimeResult, &setDateContext->time);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setDateContext, setDateContext->status == napi_ok, "invalid time",
            JsErrorCode::PARAMETER_ERROR);
        setDateContext->status = napi_ok;
    };
    setDateContext->GetCbInfo(env, info, inputParser);
    auto executor = [setDateContext]() {
        auto innerCode = TimeServiceClient::GetInstance()->SetTimeV9(setDateContext->time);
        if (innerCode != JsErrorCode::ERROR_OK) {
            setDateContext->errCode = innerCode;
            setDateContext->status = napi_generic_failure;
        }
    };
    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, setDateContext, "SetDate", executor, complete);
}

napi_value NapiSystemDateTime::GetRealActiveTime(napi_env env, napi_callback_info info)
{
    struct GetRealActiveTimeContext : public ContextBase {
        int64_t time = 0;
        bool isNano = false;
    };
    GetRealActiveTimeContext *getRealActiveTimeContext = new GetRealActiveTimeContext();
    auto inputParser = [env, getRealActiveTimeContext](size_t argc, napi_value *argv) {
        if (argc >= ARGC_ONE) {
            getRealActiveTimeContext->status =
                napi_get_value_bool(env, argv[ARGV_FIRST], &getRealActiveTimeContext->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, getRealActiveTimeContext,
            getRealActiveTimeContext->status == napi_ok, "invalid isNano", JsErrorCode::PARAMETER_ERROR);
        getRealActiveTimeContext->status = napi_ok;
    };
    getRealActiveTimeContext->GetCbInfo(env, info, inputParser);
    auto executor = [getRealActiveTimeContext]() {
        int32_t innerCode;
        if (getRealActiveTimeContext->isNano) {
            innerCode = TimeServiceClient::GetInstance()->GetMonotonicTimeNs(getRealActiveTimeContext->time);
        } else {
            innerCode = TimeServiceClient::GetInstance()->GetMonotonicTimeMs(getRealActiveTimeContext->time);
        }
        if (innerCode != JsErrorCode::ERROR_OK) {
            getRealActiveTimeContext->errCode = NapiUtils::ConvertErrorCode(innerCode);
            getRealActiveTimeContext->status = napi_generic_failure;
        }
    };
    auto complete = [env, getRealActiveTimeContext](napi_value &output) {
        getRealActiveTimeContext->status = napi_create_int64(env, getRealActiveTimeContext->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, getRealActiveTimeContext,
            "convert native object to javascript object failed", JsErrorCode::ERROR);
    };
    return NapiAsyncWork::Enqueue(env, getRealActiveTimeContext, "GetRealActiveTime", executor, complete);
}

napi_value NapiSystemDateTime::GetCurrentTime(napi_env env, napi_callback_info info)
{
    struct GetCurrentTimeContext : public ContextBase {
        int64_t time = 0;
        bool isNano = false;
    };
    GetCurrentTimeContext *getCurrentTimeContext = new GetCurrentTimeContext();
    auto inputParser = [env, getCurrentTimeContext](size_t argc, napi_value *argv) {
        if (argc >= ARGC_ONE) {
            getCurrentTimeContext->status = napi_get_value_bool(env, argv[ARGV_FIRST], &getCurrentTimeContext->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, getCurrentTimeContext, getCurrentTimeContext->status == napi_ok,
            "invalid isNano", JsErrorCode::PARAMETER_ERROR);
        getCurrentTimeContext->status = napi_ok;
    };
    getCurrentTimeContext->GetCbInfo(env, info, inputParser);
    auto executor = [getCurrentTimeContext]() {
        int32_t innerCode;
        if (getCurrentTimeContext->isNano) {
            innerCode = TimeServiceClient::GetInstance()->GetWallTimeNs(getCurrentTimeContext->time);
        } else {
            innerCode = TimeServiceClient::GetInstance()->GetWallTimeMs(getCurrentTimeContext->time);
        }
        if (innerCode != JsErrorCode::ERROR_OK) {
            getCurrentTimeContext->errCode = innerCode;
            getCurrentTimeContext->status = napi_generic_failure;
        }
    };
    auto complete = [getCurrentTimeContext, env](napi_value &output) {
        getCurrentTimeContext->status = napi_create_int64(env, getCurrentTimeContext->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, getCurrentTimeContext,
            "convert native object to javascript object failed", JsErrorCode::ERROR);
    };
    return NapiAsyncWork::Enqueue(env, getCurrentTimeContext, "GetCurrentTime", executor, complete);
}

napi_value NapiSystemDateTime::GetRealTime(napi_env env, napi_callback_info info)
{
    struct GetRealTimeContext : public ContextBase {
        int64_t time = 0;
        bool isNano = false;
    };
    GetRealTimeContext *getRealTimeContext = new GetRealTimeContext();
    auto inputParser = [env, getRealTimeContext](size_t argc, napi_value *argv) {
        if (argc >= ARGC_ONE) {
            getRealTimeContext->status = napi_get_value_bool(env, argv[ARGV_FIRST], &getRealTimeContext->isNano);
        }
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, getRealTimeContext, getRealTimeContext->status == napi_ok,
            "invalid isNano", JsErrorCode::PARAMETER_ERROR);
        getRealTimeContext->status = napi_ok;
    };
    getRealTimeContext->GetCbInfo(env, info, inputParser);
    auto executor = [getRealTimeContext]() {
        int32_t innerCode;
        if (getRealTimeContext->isNano) {
            innerCode = TimeServiceClient::GetInstance()->GetBootTimeNs(getRealTimeContext->time);
        } else {
            innerCode = TimeServiceClient::GetInstance()->GetBootTimeMs(getRealTimeContext->time);
        }
        if (innerCode != JsErrorCode::ERROR_OK) {
            getRealTimeContext->errCode = innerCode;
            getRealTimeContext->status = napi_generic_failure;
        }
    };
    auto complete = [getRealTimeContext](napi_value &output) {
        getRealTimeContext->status = napi_create_int64(getRealTimeContext->env, getRealTimeContext->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, getRealTimeContext,
            "convert native object to javascript object failed", JsErrorCode::ERROR);
    };
    return NapiAsyncWork::Enqueue(env, getRealTimeContext, "GetRealTime", executor, complete);
}

napi_value NapiSystemDateTime::GetDate(napi_env env, napi_callback_info info)
{
    struct GetDateContext : public ContextBase {
        int64_t time = 0;
    };
    GetDateContext *getDateContext = new GetDateContext();
    auto inputParser = [env, getDateContext](size_t argc, napi_value *argv) { getDateContext->status = napi_ok; };
    getDateContext->GetCbInfo(env, info, inputParser);
    auto executor = [getDateContext]() {
        auto innerCode = TimeServiceClient::GetInstance()->GetWallTimeMs(getDateContext->time);
        if (innerCode != JsErrorCode::ERROR_OK) {
            getDateContext->errCode = innerCode;
            getDateContext->status = napi_generic_failure;
        }
    };
    auto complete = [env, getDateContext](napi_value &output) {
        getDateContext->status = napi_create_date(env, getDateContext->time, &output);
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, getDateContext,
            "convert native object to javascript object failed", JsErrorCode::ERROR);
    };

    return NapiAsyncWork::Enqueue(env, getDateContext, "GetDate", executor, complete);
}

napi_value NapiSystemDateTime::SetTimezone(napi_env env, napi_callback_info info)
{
    struct SetTimezoneContext : public ContextBase {
        std::string timezone;
    };
    SetTimezoneContext *setTimezoneContext = new SetTimezoneContext();
    auto inputParser = [env, setTimezoneContext](size_t argc, napi_value *argv) {
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setTimezoneContext, argc >= ARGC_ONE, "invalid arguments",
            JsErrorCode::PARAMETER_ERROR);
        setTimezoneContext->status = NapiUtils::GetValue(env, argv[ARGV_FIRST], setTimezoneContext->timezone);
        CHECK_ARGS_RETURN_VOID(TIME_MODULE_JS_NAPI, setTimezoneContext, setTimezoneContext->status == napi_ok,
            "invalid timezone", JsErrorCode::PARAMETER_ERROR);
        setTimezoneContext->status = napi_ok;
    };
    setTimezoneContext->GetCbInfo(env, info, inputParser);
    auto executor = [setTimezoneContext]() {
        auto innerCode = TimeServiceClient::GetInstance()->SetTimeZoneV9(setTimezoneContext->timezone);
        if (innerCode != JsErrorCode::ERROR_OK) {
            setTimezoneContext->errCode = innerCode;
            setTimezoneContext->status = napi_generic_failure;
        }
    };
    auto complete = [env](napi_value &output) { output = NapiUtils::GetUndefinedValue(env); };
    return NapiAsyncWork::Enqueue(env, setTimezoneContext, "SetTimezone", executor, complete);
}

napi_value NapiSystemDateTime::GetTimezone(napi_env env, napi_callback_info info)
{
    struct GetTimezoneContext : public ContextBase {
        std::string timezone;
    };
    GetTimezoneContext *getTimezoneContext = new GetTimezoneContext();
    auto inputParser = [env, getTimezoneContext](size_t argc, napi_value *argv) {
        getTimezoneContext->status = napi_ok;
    };
    getTimezoneContext->GetCbInfo(env, info, inputParser);

    auto executor = [getTimezoneContext]() {
        auto innerCode = TimeServiceClient::GetInstance()->GetTimeZone(getTimezoneContext->timezone);
        if (innerCode != JsErrorCode::ERROR_OK) {
            getTimezoneContext->errCode = innerCode;
            getTimezoneContext->status = napi_generic_failure;
        }
    };
    auto complete = [env, getTimezoneContext](napi_value &output) {
        getTimezoneContext->status = napi_create_string_utf8(env, getTimezoneContext->timezone.c_str(),
            getTimezoneContext->timezone.size(), &output);
        TIME_HILOGI(TIME_MODULE_JS_NAPI, "%{public}s, ", getTimezoneContext->timezone.c_str());
        CHECK_STATUS_RETURN_VOID(TIME_MODULE_JS_NAPI, getTimezoneContext,
            "convert native object to javascript object failed", JsErrorCode::ERROR);
    };
    return NapiAsyncWork::Enqueue(env, getTimezoneContext, "GetTimezone", executor, complete);
}
} // namespace Time
} // namespace MiscServices
} // namespace OHOS