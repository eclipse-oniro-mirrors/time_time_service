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

#include "ntp_time_client.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#include "sntp_client.h"
#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr size_t NTP_MAX_SIZE = 5;
// VOTE calibration tolerance. Keep in sync with
// services/time/src/ntp_trusted_time.cpp (same value, separate layer).
constexpr int64_t MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS = 100;
constexpr size_t HALF = 2;

bool IsValidServer(const std::string &host)
{
    constexpr size_t ntpHostMaxLen = 255;
    if (host.empty() || host.size() > ntpHostMaxLen) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "invalid host length:%{public}zu", host.size());
        return false;
    }
    for (char c : host) {
        if (iscntrl(static_cast<unsigned char>(c)) || c == ' ') {
            TIME_HILOGE(TIME_MODULE_SERVICE, "invalid host char");
            return false;
        }
    }
    return true;
}

NtpServerResult RequestOne(const std::string &ntpServer, const NtpTimeOptions &options)
{
    NtpServerResult result;
    result.server = ntpServer;
    SNTPClient client;
    if (!client.RequestTime(ntpServer, options.perRequestTimeoutMs)) {
        result.success = false;
        result.errCode = E_TIME_NTP_UPDATE_FAILED;
        return result;
    }
    result.success = true;
    result.ntpTimeMillis = client.getNtpTime();
    result.clockOffsetMs = client.getClockOffset();
    result.roundTripTimeMs = client.getRoundTripTime();
    result.errCode = E_TIME_OK;
    return result;
}

// MIN_RTT: the successful candidate with the smallest RTT.
NtpServerResult SelectMinRtt(const std::vector<NtpServerResult> &results)
{
    auto it = std::min_element(results.begin(), results.end(),
        [](const NtpServerResult &a, const NtpServerResult &b) { return a.roundTripTimeMs < b.roundTripTimeMs; });
    return *it;
}

// VOTE: pure calibration semantics. Successful candidates whose clock offsets
// differ by <=100ms cluster and vote; pick the majority candidate with the best
// RTT. A single successful candidate returns directly. No trusted-time logic.
NtpServerResult SelectByVote(const std::vector<NtpServerResult> &results)
{
    if (results.size() == 1) {
        return results[0];
    }
    int32_t mostVotedCount = 0;
    bool found = false;
    NtpServerResult best;
    for (size_t i = 0; i < results.size(); i++) {
        int32_t count = 0;
        for (size_t j = 0; j < results.size(); j++) {
            if (std::abs(results[i].clockOffsetMs - results[j].clockOffsetMs) <=
                MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS) {
                count++;
            }
        }
        // Strict majority (> half). Among tied candidates keep the best RTT.
        if (count > static_cast<int32_t>(results.size() / HALF) &&
            (!found || count > mostVotedCount ||
             (count == mostVotedCount && results[i].roundTripTimeMs < best.roundTripTimeMs))) {
            mostVotedCount = count;
            best = results[i];
            found = true;
        }
    }
    if (found) {
        return best;
    }
    // No majority cluster; fall back to the fastest successful candidate.
    return SelectMinRtt(results);
}
} // namespace

int32_t NtpTimeClient::RequestTime(const std::string &ntpServer, const NtpTimeOptions &options, NtpServerResult &result)
{
    if (!IsValidServer(ntpServer)) {
        result.success = false;
        result.errCode = E_TIME_PARAMETERS_INVALID;
        return E_TIME_PARAMETERS_INVALID;
    }
    result = RequestOne(ntpServer, options);
    return result.success ? E_TIME_OK : E_TIME_NTP_UPDATE_FAILED;
}

int32_t NtpTimeClient::RequestTime(const std::vector<std::string> &ntpServers, const NtpTimeOptions &options,
    NtpServerResult &result)
{
    // Validate all inputs before any network request (zero packets on error).
    if (ntpServers.empty() || ntpServers.size() > NTP_MAX_SIZE) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "invalid ntp server list size:%{public}zu", ntpServers.size());
        result.success = false;
        result.errCode = E_TIME_PARAMETERS_INVALID;
        return E_TIME_PARAMETERS_INVALID;
    }
    for (const auto &server : ntpServers) {
        if (!IsValidServer(server)) {
            result.success = false;
            result.errCode = E_TIME_PARAMETERS_INVALID;
            return E_TIME_PARAMETERS_INVALID;
        }
    }

    std::vector<NtpServerResult> results;
    bool stopOnFirstSuccess = options.strategy == NtpSyncStrategy::FIRST_SUCCESS;
    for (const auto &server : ntpServers) {
        NtpServerResult one = RequestOne(server, options);
        if (one.success) {
            results.push_back(one);
            if (stopOnFirstSuccess) {
                break; // FIRST_SUCCESS returns the first successful candidate immediately.
            }
        }
    }
    if (results.empty()) {
        result.success = false;
        result.errCode = E_TIME_NTP_UPDATE_FAILED;
        return E_TIME_NTP_UPDATE_FAILED;
    }

    switch (options.strategy) {
        case NtpSyncStrategy::FIRST_SUCCESS:
            result = results[0];
            break;
        case NtpSyncStrategy::MIN_RTT:
            result = SelectMinRtt(results);
            break;
        case NtpSyncStrategy::VOTE:
            result = SelectByVote(results);
            break;
        default:
            TIME_HILOGE(TIME_MODULE_SERVICE, "invalid strategy:%{public}d",
                static_cast<int32_t>(options.strategy));
            result.success = false;
            result.errCode = E_TIME_PARAMETERS_INVALID;
            return E_TIME_PARAMETERS_INVALID;
    }
    return E_TIME_OK;
}
} // namespace MiscServices
} // namespace OHOS
