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

#ifndef NAPI_SYSTEM_TIME_H
#define NAPI_SYSTEM_TIME_H

#include <list>
#include <map>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace MiscServices {
namespace Time {

class NapiSystemDateTime {
public:
    static napi_value SystemDateTimeInit(napi_env env, napi_value exports);

    using OnEventHandlerType = std::function<napi_status(napi_env, napi_value)>;
    using OffEventHandlerType = std::function<napi_status(napi_env, napi_value)>;
    static std::map<int32_t, int32_t> errcode_;

private:
    static napi_value SetTime(napi_env env, napi_callback_info info);
    static napi_value GetCurrentTime(napi_env env, napi_callback_info info);
    static napi_value GetRealActiveTime(napi_env env, napi_callback_info info);
    static napi_value GetRealTime(napi_env env, napi_callback_info info);
    static napi_value SetDate(napi_env env, napi_callback_info info);
    static napi_value GetDate(napi_env env, napi_callback_info info);
    static napi_value SetTimezone(napi_env env, napi_callback_info info);
    static napi_value GetTimezone(napi_env env, napi_callback_info info);
};
} // namespace Time
} // namespace MiscServices
} // namespace OHOS
#endif // NAPI_SYSTEM_TIME_H