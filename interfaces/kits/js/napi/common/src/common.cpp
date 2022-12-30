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

#include "common.h"
#include "time_hilog_wreapper.h"

namespace OHOS {
namespace MiscServicesNapi {
using namespace OHOS::MiscServices;
napi_value GetCallbackErrorValue(napi_env env, int errCode, const char *message)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    if (errCode == ERROR_OK) {
        napi_get_undefined(env, &result);
        return result;
    }
    NAPI_CALL(env, napi_create_object(env, &result));
    if (errCode == ERROR) {
        NAPI_CALL(env, napi_create_int32(env, errCode, &eCode));
        NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));

        napi_value str;
        size_t str_len = strlen(message);
        NAPI_CALL(env, napi_create_string_utf8(env, message, str_len, &str));
        NAPI_CALL(env, napi_set_named_property(env, result, "message", str));
    }
    return result;
}

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

void SetPromise(const napi_env env, const napi_deferred deferred, int errorCode, const char *message, napi_value result)
{
    if (errorCode == MiscServices::E_TIME_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result));
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, GetCallbackErrorValue(env, errorCode, message)));
}

void SetCallback(const napi_env env, napi_ref callbackIn, int errorCode, const char *message, napi_value result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_value results[2] = { 0 };
    results[0] = GetCallbackErrorValue(env, errorCode, message);
    results[1] = result;
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGC_TWO, &results[0], &resultOut));
}

void ReturnCallbackPromise(napi_env env, const CallbackPromiseInfo &info, napi_value result)
{
    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, info.message, result);
    } else {
        SetPromise(env, info.deferred, info.errorCode, info.message, result);
    }
}

napi_value JSParaError(napi_env env, napi_ref callback)
{
    if (callback) {
        return GetCallbackErrorValue(env, ERROR, "System error");
    } else {
        napi_value promise = nullptr;
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);
        SetPromise(env, deferred, ERROR, "System error", NapiGetNull(env));
        return promise;
    }
}

napi_value ParseParametersBySetTime(napi_env env, const napi_value (&argv)[SET_TIME_MAX_PARA],
                                    size_t argc, int64_t &times, napi_ref &callback)
{
    NAPI_ASSERTP(env, argc >= SET_TIME_MAX_PARA - 1, "Wrong number of arguments");
    napi_valuetype valueType = napi_undefined;

    // argv[0]: times or date object
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERTP(env, valueType == napi_number || valueType == napi_object,
                 "Parameter error. The type of time must be number or date.");
    if (valueType == napi_number) {
        napi_get_value_int64(env, argv[0], &times);
        NAPI_ASSERTP(env, times >= 0, "Wrong argument timer. Positive number expected.");
    } else {
        bool hasProperty = false;
        napi_valuetype resValueType = napi_undefined;
        NAPI_CALL(env, napi_has_named_property(env, argv[0], "getTime", &hasProperty));
        NAPI_ASSERTP(env, hasProperty, "type expected.");
        napi_value getTimeFunc = nullptr;
        napi_get_named_property(env, argv[0], "getTime", &getTimeFunc);
        napi_value getTimeResult = nullptr;
        napi_call_function(env, argv[0], getTimeFunc, 0, nullptr, &getTimeResult);
        NAPI_CALL(env, napi_typeof(env, getTimeResult, &resValueType));
        NAPI_ASSERTP(env, resValueType == napi_number, "type mismatch");
        napi_get_value_int64(env, getTimeResult, &times);
    }

    // argv[1]:callback
    if (argc >= SET_TIME_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERTP(env, valueType == napi_function, "Parameter error. The type of callback must be function.");
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

napi_value ParseParametersBySetTimezone(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA],
                                        size_t argc, std::string &timezoneId, napi_ref &callback)
{
    NAPI_ASSERTP(env, argc >= SET_TIMEZONE_MAX_PARA - 1, "Wrong number of arguments");
    napi_valuetype valueType = napi_undefined;

    // argv[0]: timezoneid
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERTP(env, valueType == napi_string, "Parameter error. The type of timezone must be string.");
    char timeZoneChars[MAX_TIME_ZONE_ID];
    size_t copied;
    napi_get_value_string_utf8(env, argv[0], timeZoneChars, MAX_TIME_ZONE_ID - 1, &copied);
    TIME_HILOGD(TIME_MODULE_JNI, "timezone str: %{public}s", timeZoneChars);

    timezoneId = std::string(timeZoneChars);

    // argv[1]:callback
    if (argc >= SET_TIMEZONE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERTP(env, valueType == napi_function, "Parameter error. The type of callback must be function.");
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}

napi_value ParseParametersGet(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA], size_t argc,
                              napi_ref &callback)
{
    napi_valuetype valueType = napi_undefined;
    if (argc == 1) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        NAPI_ASSERTP(env, valueType == napi_function, "Parameter error. The type of callback must be function.");
        napi_create_reference(env, argv[0], 1, &callback);
    }
    return NapiGetNull(env);
}

napi_value ParseParametersGetNA(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA],
                                size_t argc, napi_ref &callback, bool *isNano)
{
    napi_valuetype valueType = napi_undefined;
    if (argc == 1) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        if (valueType == napi_function) {
            napi_create_reference(env, argv[0], 1, &callback);
        } else if (valueType == napi_boolean) {
            napi_get_value_bool(env, argv[0], isNano);
        }
    } else if (argc == ARGC_TWO) {
        napi_get_value_bool(env, argv[0], isNano);
        napi_create_reference(env, argv[1], 1, &callback);
    }
    return NapiGetNull(env);
}
} // namespace MiscServicesNapi
} // namespace OHOS