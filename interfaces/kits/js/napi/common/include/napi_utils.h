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

#ifndef NAPI_UTILS_H
#define NAPI_UTILS_H

#include <memory>
#include <string>

#include "js_native_api.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "time_hilog_wreapper.h"

namespace OHOS {
namespace MiscServices {
namespace Time {

/* check condition related to argc/argv, return and logging. */
#define CHECK_ARGS_RETURN_VOID(module, context, condition, message, code)  \
    do {                                                                   \
        if (!(condition)) {                                                \
            (context)->status = napi_invalid_arg;                          \
            (context)->errMessage = std::string(message);                  \
            (context)->errCode = code;                                     \
            TIME_HILOGE(module, "test (" #condition ") failed: " message); \
            return;                                                        \
        }                                                                  \
    } while (0)

#define CHECK_STATUS_RETURN_VOID(module, context, message, code)                       \
    do {                                                                               \
        if ((context)->status != napi_ok) {                                            \
            (context)->errMessage = std::string(message);                              \
            (context)->errCode = code;                                                 \
            TIME_HILOGE(module, "test (context->status == napi_ok) failed: " message); \
            return;                                                                    \
        }                                                                              \
    } while (0)

/* check condition, return and logging if condition not true. */
#define CHECK_RETURN(module, condition, message, retVal)                   \
    do {                                                                   \
        if (!(condition)) {                                                \
            TIME_HILOGE(module, "test (" #condition ") failed: " message); \
            return retVal;                                                 \
        }                                                                  \
    } while (0)

#define CHECK_RETURN_VOID(module, condition, message)                      \
    do {                                                                   \
        if (!(condition)) {                                                \
            TIME_HILOGE(module, "test (" #condition ") failed: " message); \
            return;                                                        \
        }                                                                  \
    } while (0)

constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t ARGC_THERE = 3;

constexpr size_t ARGV_FIRST = 0;
constexpr size_t ARGV_SECOND = 1;
constexpr size_t ARGV_THIRD = 2;

const int32_t ERROR_OK = 0;
const int32_t ERROR = 13000001;
const int32_t PERMISSION_ERROR = 201;
const int32_t SYSTEM_APP_ERROR = 202;
const int32_t PARAMETER_ERROR = 401;

constexpr const char *SYSTEM_ERROR = "system error";

struct JsErrorInfo {
    int32_t code = ERROR_OK;
    std::string message;
};
class NapiUtils {
public:
    static JsErrorInfo ConvertErrorCode(int32_t timeErrorCode);
    static napi_value CreateNapiNumber(napi_env env, int32_t objName);
    static napi_value GetUndefinedValue(napi_env env);
    static napi_status GetValue(napi_env env, napi_value in, std::string &out);
    static void SetCallback(const napi_env &env, const napi_ref &callbackIn, const int &errorCode, const char *message,
        const napi_value &result);
    static napi_status ThrowError(napi_env env, const char *napiMessage, int32_t napiCode);
};
} // namespace Time
} // namespace MiscServices
} // namespace OHOS

#endif // NAPI_UTILS_H