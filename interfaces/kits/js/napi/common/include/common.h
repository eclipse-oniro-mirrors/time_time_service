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

#define NAPI_ASSERTP(env, assertion, message) \
    NAPI_ASSERTS_BASE(env, assertion, std::to_string(ERROR).c_str(), message, nullptr)

namespace OHOS {
namespace MiscServicesNapi {

constexpr int32_t SET_TIME_MAX_PARA = 2;
constexpr int32_t SET_TIMEZONE_MAX_PARA = 2;

constexpr int32_t CREATE_MAX_PARA = 2;
constexpr int32_t START_MAX_PARA = 3;
constexpr int32_t STOP_MAX_PARA = 2;
constexpr int32_t DESTROY_MAX_PARA = 2;

constexpr int32_t MAX_TIME_ZONE_ID = 1024;
constexpr int32_t INVALID_TIME = -1;

constexpr int32_t ERROR_OK = 0;
constexpr int32_t ERROR = -1;

constexpr int32_t ARGC_TWO = 2;

struct CallbackPromiseInfo {
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    bool isCallback = false;
    int errorCode = ERROR_OK;
    const char *message = "";
};

napi_value GetCallbackErrorValue(napi_env env, int errCode, const char *message);
napi_value NapiGetNull(napi_env env);
void SetPromise(const napi_env env, const napi_deferred deferred, int errorCode, const char *message,
    napi_value result);
void SetCallback(const napi_env env, napi_ref callbackIn, int errorCode, const char *message, napi_value result);
void ReturnCallbackPromise(napi_env env, const CallbackPromiseInfo &info, napi_value result);
napi_value JSParaError(napi_env env, napi_ref callback);
napi_value ParseParametersBySetTime(napi_env env, const napi_value (&argv)[SET_TIME_MAX_PARA], size_t argc,
    int64_t &times, napi_ref &callback);
napi_value ParseParametersBySetTimezone(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA], size_t argc,
    std::string &timezoneId, napi_ref &callback);
napi_value ParseParametersGet(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA], size_t argc,
    napi_ref &callback);
napi_value ParseParametersGetNA(napi_env env, const napi_value (&argv)[SET_TIMEZONE_MAX_PARA], size_t argc,
    napi_ref &callback, bool *isNano);
} // namespace MiscServicesNapi
} // namespace OHOS

#endif // TIME_TIME_SERVICE_COMMON_H