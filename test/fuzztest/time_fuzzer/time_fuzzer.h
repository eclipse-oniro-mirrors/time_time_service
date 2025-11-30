/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef TIME_FUZZER_H
#define TIME_FUZZER_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include "time_service_client.h"
#include "itimer_info.h"
#include "simple_timer_info.h"

#define FUZZ_PROJECT_NAME "time_fuzzer"

namespace OHOS
{
    namespace MiscServices
    {

        // 操作类型枚举
        enum class FuzzOperationType : uint8_t
        {
            // Time API (16个)
            SET_TIME = 0,
            SET_TIME_V9,
            SET_AUTO_TIME,
            SET_TIMEZONE,
            SET_TIMEZONE_V9,
            GET_TIMEZONE,
            GET_WALL_TIME_MS,
            GET_WALL_TIME_NS,
            GET_BOOT_TIME_MS,
            GET_BOOT_TIME_NS,
            GET_MONOTONIC_TIME_MS,
            GET_MONOTONIC_TIME_NS,
            GET_THREAD_TIME_MS,
            GET_THREAD_TIME_NS,
            GET_NTP_TIME_MS,
            GET_REAL_TIME_MS,

            // Timer API (12个)
            CREATE_TIMER,
            CREATE_TIMER_V9,
            START_TIMER,
            START_TIMER_V9,
            STOP_TIMER,
            STOP_TIMER_V9,
            DESTROY_TIMER,
            DESTROY_TIMER_ASYNC,
            PROXY_TIMER,
            RESET_ALL_PROXY,
            ADJUST_TIMER,
            SET_TIMER_EXEMPTION,
            SET_ADJUST_POLICY,

            // 特殊场景 (5个)
            BOUNDARY_TEST,
            CONCURRENT_TEST,
            COMBO_SCENARIO,
            TIMER_LIFECYCLE,
            STRESS_TEST,

            OP_MAX
        };

        class TimeFuzzer
        {
        public:
            TimeFuzzer();
            ~TimeFuzzer();

            void FuzzTest(const uint8_t *data, size_t size);

        private:
            // 工具方法
            bool IsOffsetValid(size_t offset, size_t size, size_t needSize);
            int64_t ExtractInt64(const uint8_t *data, size_t &offset, size_t size);
            uint64_t ExtractUint64(const uint8_t *data, size_t &offset, size_t size);
            int32_t ExtractInt32(const uint8_t *data, size_t &offset, size_t size);
            uint32_t ExtractUint32(const uint8_t *data, size_t &offset, size_t size);
            uint8_t ExtractUint8(const uint8_t *data, size_t &offset, size_t size);
            bool ExtractBool(const uint8_t *data, size_t &offset, size_t size);
            std::string ExtractString(const uint8_t *data, size_t &offset, size_t size, size_t maxLen);
            std::vector<int> ExtractIntVector(const uint8_t *data, size_t &offset, size_t size);
            std::vector<std::string> ExtractStringVector(const uint8_t *data, size_t &offset, size_t size);
            std::unordered_set<std::string> ExtractStringSet(const uint8_t *data, size_t &offset, size_t size);

            // Time API Fuzz方法
            void FuzzSetTime(const uint8_t *data, size_t size);
            void FuzzSetTimeV9(const uint8_t *data, size_t size);
            void FuzzSetAutoTime(const uint8_t *data, size_t size);
            void FuzzSetTimeZone(const uint8_t *data, size_t size);
            void FuzzSetTimeZoneV9(const uint8_t *data, size_t size);
            void FuzzGetTimeZone(const uint8_t *data, size_t size);
            void FuzzGetWallTimeMs(const uint8_t *data, size_t size);
            void FuzzGetWallTimeNs(const uint8_t *data, size_t size);
            void FuzzGetBootTimeMs(const uint8_t *data, size_t size);
            void FuzzGetBootTimeNs(const uint8_t *data, size_t size);
            void FuzzGetMonotonicTimeMs(const uint8_t *data, size_t size);
            void FuzzGetMonotonicTimeNs(const uint8_t *data, size_t size);
            void FuzzGetThreadTimeMs(const uint8_t *data, size_t size);
            void FuzzGetThreadTimeNs(const uint8_t *data, size_t size);
            void FuzzGetNtpTimeMs(const uint8_t *data, size_t size);
            void FuzzGetRealTimeMs(const uint8_t *data, size_t size);

            // Timer API Fuzz方法
            void FuzzCreateTimer(const uint8_t *data, size_t size);
            void FuzzCreateTimerV9(const uint8_t *data, size_t size);
            void FuzzStartTimer(const uint8_t *data, size_t size);
            void FuzzStartTimerV9(const uint8_t *data, size_t size);
            void FuzzStopTimer(const uint8_t *data, size_t size);
            void FuzzStopTimerV9(const uint8_t *data, size_t size);
            void FuzzDestroyTimer(const uint8_t *data, size_t size);
            void FuzzDestroyTimerAsync(const uint8_t *data, size_t size);
            void FuzzProxyTimer(const uint8_t *data, size_t size);
            void FuzzResetAllProxy(const uint8_t *data, size_t size);
            void FuzzAdjustTimer(const uint8_t *data, size_t size);
            void FuzzSetTimerExemption(const uint8_t *data, size_t size);
            void FuzzSetAdjustPolicy(const uint8_t *data, size_t size);

            // 特殊场景Fuzz方法
            void FuzzBoundaryTest(const uint8_t *data, size_t size);
            void FuzzConcurrentTest(const uint8_t *data, size_t size);
            void FuzzComboScenario(const uint8_t *data, size_t size);
            void FuzzTimerLifecycle(const uint8_t *data, size_t size);
            void FuzzStressTest(const uint8_t *data, size_t size);

            sptr<TimeServiceClient> client_;
            std::vector<uint64_t> createdTimers_;
        };

    } // namespace MiscServices
} // namespace OHOS

#endif // TIME_FUZZER_H
