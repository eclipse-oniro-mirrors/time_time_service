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

#include "napi_utils.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "time_common.h"

namespace OHOS {
namespace MiscServices {
namespace Time {

static constexpr int32_t STR_MAX_LENGTH = 4096;
static constexpr size_t STR_TAIL_LENGTH = 1;

int32_t NapiUtils::ConvertErrorCode(int32_t timeErrorCode)
{
    switch (timeErrorCode) {
        case MiscServices::E_TIME_NOT_SYSTEM_APP:
            return static_cast<int32_t>(JsErrorCode::SYSTEM_APP_ERROR);
        case MiscServices::E_TIME_NO_PERMISSION:
            return static_cast<int32_t>(JsErrorCode::PERMISSION_ERROR);
        case MiscServices::E_TIME_PARAMETERS_INVALID:
            return static_cast<int32_t>(JsErrorCode::PARAMETER_ERROR);
        default:
            return JsErrorCode::ERROR;
    }
}

napi_value NapiUtils::CreateNapiNumber(napi_env env, int32_t objName)
{
    napi_value prop = nullptr;
    napi_create_int32(env, objName, &prop);
    return prop;
}

napi_value NapiUtils::GetUndefinedValue(napi_env env)
{
    napi_value result{};
    napi_get_undefined(env, &result);
    return result;
}

napi_status NapiUtils::GetValue(napi_env env, napi_value in, std::string &out)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, in, &type);
    CHECK_RETURN(TIME_MODULE_JS_NAPI, (status == napi_ok) && (type == napi_string), "invalid type", napi_invalid_arg);
    size_t maxLen = STR_MAX_LENGTH;
    status = napi_get_value_string_utf8(env, in, nullptr, 0, &maxLen);
    if (maxLen <= 0 || maxLen >= STR_MAX_LENGTH) {
        return napi_invalid_arg;
    }
    char buf[STR_MAX_LENGTH + STR_TAIL_LENGTH]{};
    size_t len = 0;
    status = napi_get_value_string_utf8(env, in, buf, maxLen + STR_TAIL_LENGTH, &len);
    if (status == napi_ok) {
        out = std::string(buf);
    }
    return status;
}

void NapiUtils::SetCallback(const napi_env &env, const napi_ref &callbackIn, const int32_t &errorCode,
    const char *message, const napi_value &result)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);

    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    napi_get_reference_value(env, callbackIn, &callback);
    napi_value results[2] = { 0 };

    auto innerCode = ConvertErrorCode(errorCode);
    napi_value eCode = nullptr;
    napi_create_int32(env, innerCode, &eCode);
    napi_set_named_property(env, result, "code", eCode);

    napi_value str;
    napi_create_string_utf8(env, CODE_TO_MESSAGE.find(innerCode)->second.c_str(), NAPI_AUTO_LENGTH, &str);
    napi_set_named_property(env, results[0], "message", str);
    results[1] = result;
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGC_TWO, &results[0], &resultOut));
}

napi_status NapiUtils::ThrowError(napi_env env, const char *napiMessage, int32_t napiCode)
{
    napi_value message = nullptr;
    napi_value code = nullptr;
    napi_value result = nullptr;
    napi_create_string_utf8(env, napiMessage, NAPI_AUTO_LENGTH, &message);
    napi_create_error(env, nullptr, message, &result);
    napi_create_int32(env, napiCode, &code);
    napi_set_named_property(env, result, "code", code);
    napi_throw(env, result);
    return napi_ok;
}
} // namespace Time
} // namespace MiscServices
} // namespace OHOS