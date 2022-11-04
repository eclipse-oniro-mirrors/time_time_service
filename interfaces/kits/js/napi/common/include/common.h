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
#include "js_native_api.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "string"
#include "time_common.h"

#ifndef TIME_TIME_SERVICE_COMMON_H
#define TIME_TIME_SERVICE_COMMON_H

#define NAPI_ASSERTS_BASE(env, assertion, code, message, retVal) \
    do {                                                         \
        if (!(assertion)) {                                      \
            napi_throw_error((env), code, message);              \
            return retVal;                                       \
        }                                                        \
    } while (0)

#define NAPI_ASSERTP(env, assertion, message) NAPI_ASSERTS_BASE(env, assertion, CODE_401, message, nullptr)

namespace OHOS {
namespace MiscServicesNapi {
namespace {
const int SET_TIME_MAX_PARA = 2;
const int SET_TIMEZONE_MAX_PARA = 2;

const int CREATE_MAX_PARA = 2;
const int START_MAX_PARA = 3;
const int STOP_MAX_PARA = 2;
const int DESTROY_MAX_PARA = 2;

const int MAX_TIME_ZONE_ID = 1024;
const int INVALID_TIME = -1;

const int ERROR = 13000000;
const int ERROR_201 = 201;
const int ERROR_401 = 401;
const char *CODE_201 = "201";
const char *CODE_401 = "401";
} // namespace

struct CallbackPromiseInfo {
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    bool isCallback = false;
    int errorCode = MiscServices::E_TIME_OK;
    const char *message = "";
};

napi_value GetCallbackErrorValue(napi_env env, int errCode, const char *message)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    if (errCode == MiscServices::E_TIME_OK) {
        napi_get_undefined(env, &result);
        return result;
    }
    NAPI_CALL(env, napi_create_object(env, &result));
    if (errCode == MiscServices::E_TIME_NO_PERMISSION) {
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

void SetPromise(const napi_env &env, const napi_deferred &deferred, const int &errorCode, const char *message,
    const napi_value &result)
{
    if (errorCode == MiscServices::E_TIME_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result));
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, GetCallbackErrorValue(env, errorCode, message)));
}

void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int &errorCode, const char *message,
    const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_value results[2] = { 0 };
    results[0] = GetCallbackErrorValue(env, errorCode, message);
    results[1] = result;
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, 2, &results[0], &resultOut));
}

void ReturnCallbackPromise(const napi_env &env, const CallbackPromiseInfo &info, const napi_value &result)
{
    if (info.isCallback) {
        SetCallback(env, info.callback, info.errorCode, info.message, result);
    } else {
        SetPromise(env, info.deferred, info.errorCode, info.message, result);
    }
}

napi_value JSParaError(const napi_env &env, const napi_ref &callback)
{
    if (callback) {
        return GetCallbackErrorValue(env, ERROR, "System error, errorCode is 13000000.");
    } else {
        napi_value promise = nullptr;
        napi_deferred deferred = nullptr;
        napi_create_promise(env, &deferred, &promise);
        SetPromise(env, deferred, ERROR, "System error, errorCode is 13000000.", NapiGetNull(env));
        return promise;
    }
}
} // namespace MiscServicesNapi
} // namespace OHOS

#endif //TIME_TIME_SERVICE_COMMON_H