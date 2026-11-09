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

// On-device demo for the NTP engine innerkit (libntp_time_client.z.so).
// Output is plain English for non-technical readers, with the raw error code
// and millisecond timestamps shown alongside for engineers.

#include <cstdio>
#include <cstring>
#include <ctime>
#include <securec.h>
#include <string>
#include <vector>

#include "ntp_time_client.h"
#include "sntp_client.h"

using namespace OHOS::MiscServices;

namespace {
constexpr int64_t MS_PER_DAY = 24 * 60 * 60 * 1000;
constexpr int64_t MS_PER_HOUR = 60 * 60 * 1000;
constexpr int64_t MS_PER_MIN = 60 * 1000;
constexpr int64_t MS_PER_SECOND = 1000;
constexpr int64_t RTT_NORMAL_MS = 100;
constexpr int64_t RTT_SLOW_MS = 300;
// Displayed times are in Beijing time (UTC+8).
constexpr int64_t BEIJING_TZ_OFFSET_MS = 8 * MS_PER_HOUR;
// Same rule as the SA side: a device within 2s of the NTP time needs no sync.
constexpr int64_t NEED_SYNC_THRESHOLD_MS = 2000;
constexpr int64_t NANOS_PER_MS = 1000000;
constexpr double SECONDS_PER_MINUTE = 60.0;
constexpr int UPTIME_FIELD_COUNT = 2;

std::string DateTime(int64_t unixMs)
{
    time_t sec = static_cast<time_t>((unixMs + BEIJING_TZ_OFFSET_MS) / MS_PER_SECOND);
    struct tm tm {};
    gmtime_r(&sec, &tm);
    char buf[32] = {0};
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S (Beijing)", &tm) == 0) {
        return "1970-01-01 08:00:00 (Beijing)";
    }
    return std::string(buf);
}

// Current device wall-clock time (CLOCK_REALTIME) in ms. The SA's 2s
// no-calibrate check compares the wall clock with the NTP time, so the demo
// does the same here (the engine's clockOffsetMs is relative to the monotonic
// CLOCK_BOOTTIME and is not a wall-clock deviation).
int64_t WallTimeMs()
{
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<int64_t>(ts.tv_sec) * MS_PER_SECOND + ts.tv_nsec / NANOS_PER_MS;
}

// Read any clock in ms (used for diagnosing the CLOCK_BOOTTIME base).
int64_t ClockMs(clockid_t id)
{
    struct timespec ts {};
    clock_gettime(id, &ts);
    return static_cast<int64_t>(ts.tv_sec) * MS_PER_SECOND + ts.tv_nsec / NANOS_PER_MS;
}

// Forward declaration; OffsetText is defined below in this anonymous namespace.
std::string OffsetText(int64_t offsetMs);

// Print the device's three clocks and /proc/uptime so the source of a large
// clock offset can be pinned down (BOOTTIME base vs wall clock vs uptime).
void PrintSystemClocks()
{
    int64_t realtime = ClockMs(CLOCK_REALTIME);
    int64_t boottime = ClockMs(CLOCK_BOOTTIME);
    int64_t monotonic = ClockMs(CLOCK_MONOTONIC);
    printf("[System clocks]\n");
    printf("  CLOCK_REALTIME : %s  (ms=%lld)  <- device wall clock\n", DateTime(realtime).c_str(),
        static_cast<long long>(realtime));
    printf("  CLOCK_BOOTTIME : %s  (ms=%lld)  <- engine sync reference\n", DateTime(boottime).c_str(),
        static_cast<long long>(boottime));
    printf("  CLOCK_MONOTONIC: %lld ms  (time since boot)\n", static_cast<long long>(monotonic));
    FILE *f = fopen("/proc/uptime", "r");
    if (f != nullptr) {
        double up = 0.0;
        double idle = 0.0;
        if (fscanf_s(f, "%lf %lf", &up, &idle) == UPTIME_FIELD_COUNT) {
            printf("  /proc/uptime   : %.0f s (~%.1f min), idle %.0f s\n", up, up / SECONDS_PER_MINUTE, idle);
        }
        fclose(f);
    }
    printf("  BOOTTIME-MONOTONIC = %s  (BOOTTIME base vs uptime)\n",
        OffsetText(boottime - monotonic).c_str());
    printf("  BOOTTIME-REALTIME  = %s  (BOOTTIME base vs wall clock)\n",
        OffsetText(boottime - realtime).c_str());
    printf("\n");
}

// "AHEAD/BEHIND Xd Xh Xm Xs". Negative offset => local clock runs fast.
std::string OffsetText(int64_t offsetMs)
{
    bool ahead = offsetMs < 0;
    int64_t absMs = ahead ? -offsetMs : offsetMs;
    std::string text = ahead ? "AHEAD of standard time" : "BEHIND standard time";
    std::string dur;
    if (absMs >= MS_PER_DAY) {
        dur += std::to_string(absMs / MS_PER_DAY) + "d ";
        absMs %= MS_PER_DAY;
    }
    if (absMs >= MS_PER_HOUR) {
        dur += std::to_string(absMs / MS_PER_HOUR) + "h ";
        absMs %= MS_PER_HOUR;
    }
    if (absMs >= MS_PER_MIN) {
        dur += std::to_string(absMs / MS_PER_MIN) + "m ";
        absMs %= MS_PER_MIN;
    }
    if (absMs >= MS_PER_SECOND) {
        dur += std::to_string(absMs / MS_PER_SECOND) + "s";
    } else if (offsetMs != 0) {
        dur += "<1s";
    }
    return dur + " " + text;
}

std::string RttText(int64_t rttMs)
{
    if (rttMs < RTT_NORMAL_MS) {
        return std::to_string(rttMs) + " ms (normal)";
    }
    if (rttMs < RTT_SLOW_MS) {
        return std::to_string(rttMs) + " ms (slow)";
    }
    return std::to_string(rttMs) + " ms (very slow)";
}

std::string ErrorText(int32_t code)
{
    if (code == E_TIME_OK) {
        return "OK";
    }
    if (code == E_TIME_NTP_UPDATE_FAILED) {
        return "no time server reachable (network down or server unresponsive)";
    }
    if (code == E_TIME_PARAMETERS_INVALID) {
        return "invalid argument: bad server address";
    }
    return "unknown error (code " + std::to_string(static_cast<int>(code)) + ")";
}

void PrintSyncOutcome(const std::string &title, int32_t ret, const NtpServerResult &result, bool withOffset)
{
    printf("%s\n", title.c_str());
    if (ret == E_TIME_OK && result.success) {
        printf("  OK   errorCode=%d\n", static_cast<int>(result.errCode));
        printf("  Server          : %s\n", result.server.c_str());
        printf("  NTP time        : %s  (ntpTimeMillis=%lld)\n", DateTime(result.ntpTimeMillis).c_str(),
            static_cast<long long>(result.ntpTimeMillis));
        printf("  Round-trip     : %s\n", RttText(result.roundTripTimeMs).c_str());
        if (withOffset) {
            int64_t wallDiffMs = result.ntpTimeMillis - WallTimeMs();
            printf("  Clock offset   : %s  (clockOffsetMs=%lld, relative to monotonic clock)\n",
                OffsetText(result.clockOffsetMs).c_str(), static_cast<long long>(result.clockOffsetMs));
            printf("  Verify offset  : expected(ntpTime-BOOTTIME_now)=%lld ms vs engine clockOffsetMs=%lld\n",
                static_cast<long long>(result.ntpTimeMillis - ClockMs(CLOCK_BOOTTIME)),
                static_cast<long long>(result.clockOffsetMs));
            printf("  Local clock    : %s  (device wall time)\n", DateTime(WallTimeMs()).c_str());
            printf("  Clock deviation: %s  (vs standard time)\n", OffsetText(wallDiffMs).c_str());
            if (wallDiffMs < -NEED_SYNC_THRESHOLD_MS || wallDiffMs > NEED_SYNC_THRESHOLD_MS) {
                printf("  Verdict        : offset > 2s -> time calibration recommended\n");
            } else {
                printf("  Verdict        : offset within 2s -> no calibration needed\n");
            }
        }
    } else {
        printf("  FAILED errorCode=%d  (%s)\n", static_cast<int>(ret), ErrorText(ret).c_str());
    }
    printf("\n");
}

void RunSingleServer(const std::string &title, const std::string &server, uint32_t timeoutMs)
{
    NtpTimeOptions options;
    options.perRequestTimeoutMs = timeoutMs;
    NtpServerResult result;
    int32_t ret = NtpTimeClient::RequestTime(server, options, result);
    PrintSyncOutcome(title + " " + server, ret, result, true);
}

void RunConnectivity(const std::string &title, const std::vector<std::string> &servers, uint32_t timeoutMs)
{
    printf("%s\n", title.c_str());
    NtpTimeOptions options;
    options.perRequestTimeoutMs = timeoutMs;
    for (const auto &server : servers) {
        NtpServerResult one;
        int32_t oneRet = NtpTimeClient::RequestTime(server, options, one);
        if (oneRet == E_TIME_OK && one.success) {
            printf("  OK   %-24s ntpTime=%lld (%s)  rtt=%s\n", server.c_str(),
                static_cast<long long>(one.ntpTimeMillis), DateTime(one.ntpTimeMillis).c_str(),
                RttText(one.roundTripTimeMs).c_str());
        } else {
            printf("  FAIL %-24s errorCode=%d  (%s)\n", server.c_str(), static_cast<int>(oneRet),
                ErrorText(oneRet).c_str());
        }
    }
    printf("\n");
}

NtpServerResult RunStrategy(const std::string &title, NtpSyncStrategy strategy,
    const std::vector<std::string> &servers, uint32_t timeoutMs)
{
    NtpTimeOptions options;
    options.strategy = strategy;
    options.perRequestTimeoutMs = timeoutMs;
    NtpServerResult result;
    int32_t ret = NtpTimeClient::RequestTime(servers, options, result);
    PrintSyncOutcome(title, ret, result, true);
    return result;
}

void RunDirectCall(const std::string &title, const std::string &server)
{
    printf("%s\n", title.c_str());
    SNTPClient client;
    if (client.RequestTime(server)) {
        printf("  OK   ntpTime=%lld (%s)  rtt=%s\n", static_cast<long long>(client.getNtpTime()),
            DateTime(client.getNtpTime()).c_str(), RttText(client.getRoundTripTime()).c_str());
    } else {
        printf("  FAILED  (no time server reachable)\n");
    }
    printf("\n");
}

std::string StrategyName(NtpSyncStrategy strategy)
{
    switch (strategy) {
        case NtpSyncStrategy::FIRST_SUCCESS:
            return "first success (FIRST_SUCCESS)";
        case NtpSyncStrategy::MIN_RTT:
            return "fastest reply (MIN_RTT)";
        case NtpSyncStrategy::VOTE:
            return "majority vote (VOTE)";
        default:
            return "unknown strategy";
    }
}

// Numbered section title; the counter keeps numbering contiguous whether one
// or both strategies run.
std::string SectionTitle(int &section, const std::string &name)
{
    return "[" + std::to_string(section++) + ". " + name + "]";
}
// Split a comma-separated server list into individual servers.
void SplitServers(const std::string &arg, std::vector<std::string> &servers)
{
    size_t pos = 0;
    while (pos < arg.size()) {
        size_t comma = arg.find(',', pos);
        std::string server = comma == std::string::npos ? arg.substr(pos) : arg.substr(pos, comma - pos);
        if (!server.empty()) {
            servers.emplace_back(server);
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
}

// Parse argv into servers/options. Returns 0 on success, nonzero on bad args.
int ParseArgs(int argc, char *argv[], std::vector<std::string> &servers, bool &strategySet,
    NtpSyncStrategy &chosen, uint32_t &timeoutMs)
{
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.rfind("--strategy=", 0) == 0) {
            std::string value = arg.substr(std::string("--strategy=").size());
            if (value == "first_success") {
                chosen = NtpSyncStrategy::FIRST_SUCCESS;
            } else if (value == "min_rtt") {
                chosen = NtpSyncStrategy::MIN_RTT;
            } else if (value == "vote") {
                chosen = NtpSyncStrategy::VOTE;
            } else {
                printf("unknown strategy '%s' (first_success | min_rtt | vote)\n", value.c_str());
                return 1;
            }
            strategySet = true;
        } else if (arg.rfind("--timeout=", 0) == 0) {
            std::string value = arg.substr(std::string("--timeout=").size());
            bool digits = !value.empty() && value.find_first_not_of("0123456789") == std::string::npos;
            if (!digits) {
                printf("invalid timeout '%s' (positive milliseconds expected)\n", value.c_str());
                return 1;
            }
            uint32_t t = static_cast<uint32_t>(std::stoul(value));
            if (t == 0) {
                printf("timeout must be > 0\n");
                return 1;
            }
            timeoutMs = t;
        } else {
            SplitServers(arg, servers);
        }
    }
    return 0;
}

void PrintHeader(const std::vector<std::string> &servers)
{
    printf("========================================================\n");
    printf("  NTP Time Sync Test (time_service sync engine)\n");
    printf("--------------------------------------------------------\n");
    printf("  Purpose: fetch the standard time from NTP servers and\n");
    printf("  check how far the local clock has drifted.\n");
    printf("  Note: times below are in Beijing time (UTC+8); a negative\n");
    printf("  clock offset means the local clock runs ahead of standard time.\n");
    printf("========================================================\n\n");

    printf("[Servers under test] %zu\n", servers.size());
    for (const auto &s : servers) {
        printf("  - %s\n", s.c_str());
    }
    printf("\n");
}
} // namespace

int main(int argc, char *argv[])
{
    std::vector<std::string> servers;
    bool strategySet = false;
    NtpSyncStrategy chosen = NtpSyncStrategy::FIRST_SUCCESS;
    uint32_t timeoutMs = 5000;

    if (ParseArgs(argc, argv, servers, strategySet, chosen, timeoutMs) != 0) {
        return 1;
    }
    if (servers.empty()) {
        servers.emplace_back("1.cn.pool.ntp.org");
        servers.emplace_back("time.windows.com");
    }

    PrintHeader(servers);
    PrintSystemClocks();

    int section = 1;
    if (!strategySet) {
        RunSingleServer(SectionTitle(section, "Single-server sync"), servers[0], timeoutMs);
    }
    RunConnectivity(SectionTitle(section, "Server connectivity"), servers, timeoutMs);

    NtpServerResult summary;
    if (strategySet) {
        summary = RunStrategy(SectionTitle(section, "Strategy: " + StrategyName(chosen)), chosen, servers, timeoutMs);
    } else {
        RunStrategy(SectionTitle(section, "Strategy: " + StrategyName(NtpSyncStrategy::FIRST_SUCCESS)),
            NtpSyncStrategy::FIRST_SUCCESS, servers, timeoutMs);
        RunStrategy(SectionTitle(section, "Strategy: " + StrategyName(NtpSyncStrategy::MIN_RTT)),
            NtpSyncStrategy::MIN_RTT, servers, timeoutMs);
        summary = RunStrategy(SectionTitle(section, "Strategy: " + StrategyName(NtpSyncStrategy::VOTE)),
            NtpSyncStrategy::VOTE, servers, timeoutMs);
    }
    if (!strategySet) {
        RunDirectCall(SectionTitle(section, "Direct SNTPClient call"), servers[0]);
    }

    printf("========================================================\n");
    if (summary.success) {
        int64_t wallDiffMs = summary.ntpTimeMillis - WallTimeMs();
        printf("  Result: sync OK; local clock is %s  (vs standard time)\n", OffsetText(wallDiffMs).c_str());
    } else {
        printf("  Result: sync FAILED, cannot obtain standard time\n");
    }
    printf("========================================================\n");
    return 0;
}
