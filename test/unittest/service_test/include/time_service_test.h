/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef TIME_SERVICE_TEST_H
#define TIME_SERVICE_TEST_H

#include <atomic>

constexpr int UID_PROXY_OFFSET = 32;

std::atomic<int> g_data1(0);
void TimeOutCallback1(void)
{
    g_data1 += 1;
}

std::atomic<int> g_data2(0);
void TimeOutCallback2(void)
{
    g_data2 += 1;
}

uint64_t GetProxyKey(int uid, int pid)
{
    uint64_t key = (static_cast<uint64_t>(uid) << UID_PROXY_OFFSET) | static_cast<uint64_t>(pid);
    return key;
}

#endif // TIME_SERVICE_TEST_H