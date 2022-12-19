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

#include "napi_async_callback.h"

#include <memory>

#include "napi_utils.h"

namespace OHOS {
namespace MiscServices {
namespace Time {
NapiAsyncCallback::NapiAsyncCallback(napi_env env) : env_(env)
{
    if (env != nullptr) {
        napi_get_uv_event_loop(env, &loop_);
    }
}

NapiAsyncCallback::~NapiAsyncCallback()
{
    TIME_HILOGD(TIME_MODULE_JS_NAPI, "no memory leak for queue-callback");
    env_ = nullptr;
}

napi_env NapiAsyncCallback::GetEnv() const
{
    return env_;
}

void NapiAsyncCallback::AfterWorkCallback(uv_work_t *work, int aStatus)
{
    std::shared_ptr<DataContext> context(static_cast<DataContext *>(work->data), [work](DataContext *ptr) {
        delete ptr;
        delete work;
    });

    int argc = 0;
    napi_value argv[ARGC_MAX] = { nullptr };
    if (context->getter) {
        argc = ARGC_MAX;
        context->getter(context->env, argc, argv);
    }

    TIME_HILOGI(TIME_MODULE_JS_NAPI, "queue uv_after_work_cb");
    napi_value global{};
    napi_get_global(context->env, &global);
    napi_value function{};
    napi_get_reference_value(context->env, context->method, &function);
    napi_value result;
    napi_status status = napi_call_function(context->env, global, function, argc, argv, &result);
    if (status != napi_ok) {
        TIME_HILOGE(TIME_MODULE_JS_NAPI, "call function failed status=%{public}d.", status);
    }
}

void NapiAsyncCallback::Call(napi_ref method, NapiArgsGetter getter)
{
    CHECK_RETURN_VOID(TIME_MODULE_JS_NAPI, loop_ != nullptr, "loop_ is nullptr");
    CHECK_RETURN_VOID(TIME_MODULE_JS_NAPI, method != nullptr, "method is nullptr");

    auto *work = new (std::nothrow) uv_work_t;
    CHECK_RETURN_VOID(TIME_MODULE_JS_NAPI, work != nullptr, "no memory for uv_work_t");

    work->data = new DataContext{ env_, method, std::move(getter) };
    int res = uv_queue_work(
        loop_, work, [](uv_work_t *work) {}, AfterWorkCallback);
    CHECK_RETURN_VOID(TIME_MODULE_JS_NAPI, res == 0, "uv queue work failed");
}
} // namespace Time
} // namespace MiscServices
} // namespace OHOS