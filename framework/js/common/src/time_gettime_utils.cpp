/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "time_gettime_utils.h"

#ifdef TIME_GETTIME_RANDOM

#include <ctime>
#include <mutex>
#include <random>

namespace OHOS {
namespace MiscServices {
namespace Time {

namespace {
constexpr int64_t SECONDS_TO_MILLI = 1000;
constexpr int64_t NANO_PER_MILLI = 1000000;
constexpr int64_t FIRST_RANDOM_MAX = 900000;
constexpr int64_t INCREMENT_MIN = 300;
constexpr int64_t INCREMENT_MAX = 500;
constexpr int64_t NO_INCREMENT_THRESHOLD = 990000;

std::mutex g_lastNsMutex;
int64_t g_lastNs = 0;

int64_t RandomFirstFraction()
{
    thread_local std::mt19937_64 rng{std::random_device{}()};
    thread_local std::uniform_int_distribution<int64_t> dist(1, FIRST_RANDOM_MAX);
    return dist(rng);
}

int64_t RandomIncrement()
{
    thread_local std::mt19937_64 rng{std::random_device{}()};
    thread_local std::uniform_int_distribution<int64_t> dist(INCREMENT_MIN, INCREMENT_MAX);
    return dist(rng);
}
} // namespace

int64_t GetMonotoneWallTimeNs()
{
    struct timespec ts {};
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        return -1;
    }
    int64_t ms = ts.tv_sec * SECONDS_TO_MILLI + ts.tv_nsec / NANO_PER_MILLI;
    int64_t result;

    std::lock_guard<std::mutex> lock(g_lastNsMutex);
    int64_t lastMs = g_lastNs / NANO_PER_MILLI;
    if (ms != lastMs) {
        result = ms * NANO_PER_MILLI + RandomFirstFraction();
        if (ms > lastMs && result <= g_lastNs) {
            result = g_lastNs + 1;
        }
    } else if (g_lastNs % NANO_PER_MILLI >= NO_INCREMENT_THRESHOLD) {
        result = g_lastNs + 1;
    } else {
        result = g_lastNs + RandomIncrement();
    }
    g_lastNs = result;
    return result;
}

} // namespace Time
} // namespace MiscServices
} // namespace OHOS

#endif // TIME_GETTIME_RANDOM
