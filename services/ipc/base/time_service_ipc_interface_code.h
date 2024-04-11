/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TIME_SERVICE_IPC_INTERFACE_CODE_H
#define TIME_SERVICE_IPC_INTERFACE_CODE_H

/* SAID: 3702*/
namespace OHOS {
namespace MiscServices {
enum class TimeServiceIpcInterfaceCode {
    SET_TIME = 0,
    SET_TIME_ZONE,
    GET_TIME_ZONE,
    GET_WALL_TIME_MILLI,
    GET_WALL_TIME_NANO,
    GET_BOOT_TIME_MILLI,
    GET_BOOT_TIME_NANO,
    GET_MONO_TIME_MILLI,
    GET_MONO_TIME_NANO,
    GET_THREAD_TIME_MILLI,
    GET_THREAD_TIME_NANO,
    CREATE_TIMER,
    START_TIMER,
    STOP_TIMER,
    DESTROY_TIMER,
    PROXY_TIMER,
    PID_PROXY_TIMER,
    RESET_ALL_PROXY,
    ADJUST_TIMER,
    SET_TIMER_EXEMPTION,
};
} // namespace MiscServices
} // namespace OHOS

#endif // TIME_SERVICE_IPC_INTERFACE_CODE_H