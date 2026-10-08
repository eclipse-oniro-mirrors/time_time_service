/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef NTP_TIME_CLIENT_NTP_TIME_CLIENT_H
#define NTP_TIME_CLIENT_NTP_TIME_CLIENT_H

#include <cstdint>
#include <string>
#include <vector>

#include "time_common.h"

namespace OHOS {
namespace MiscServices {

// Calibration strategy for the multi-server request. Extensible; only
// calibration semantics are provided (no trusted-time logic, Q-8/Q-9).
enum class NtpSyncStrategy : int32_t {
    FIRST_SUCCESS = 0, // Return the first successful candidate.
    MIN_RTT = 1,       // Return the successful candidate with the smallest RTT.
    VOTE = 2,          // Calibration vote: cluster successful candidates whose
                       // clock offsets differ by <=100ms, majority vote, pick the
                       // best RTT; a single successful candidate returns directly.
};

struct NtpTimeOptions {
    // Calibration strategy; only used by the multi-server overload.
    NtpSyncStrategy strategy = NtpSyncStrategy::FIRST_SUCCESS;
    // Per-request timeout limit in milliseconds (default 5000, same as current SNTP).
    uint32_t perRequestTimeoutMs = 5000;
};

struct NtpServerResult {
    std::string server;
    bool success = false;
    int64_t ntpTimeMillis = 0;
    int64_t clockOffsetMs = 0;
    int64_t roundTripTimeMs = 0;
    int32_t errCode = E_TIME_OK;
};

// Pure NTP request engine: single-shot, stateless, no clock writing, no
// scheduling, no trusted-time logic. Retry is left to the caller.
class NtpTimeClient {
public:
    // Single-server NTP request. Blocks the caller thread for up to
    // perRequestTimeoutMs. Returns 0 on success and fills result.
    static int32_t RequestTime(const std::string &ntpServer, const NtpTimeOptions &options, NtpServerResult &result);
    // Multi-server NTP request (1~5 servers). Blocks the caller thread for up
    // to perRequestTimeoutMs per server. Returns 0 on success; the result is
    // the candidate selected by options.strategy.
    static int32_t RequestTime(const std::vector<std::string> &ntpServers, const NtpTimeOptions &options,
        NtpServerResult &result);
};
} // namespace MiscServices
} // namespace OHOS
#endif // NTP_TIME_CLIENT_NTP_TIME_CLIENT_H
