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


#include "ntptrustedtime_state_fuzzer.h"

#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#define private public // NOLINT
#include "ntp_trusted_time.h"
#undef private

namespace OHOS {
namespace {
constexpr int64_t HOURS_PER_DAY = 24LL;
constexpr int64_t MINUTES_PER_HOUR = 60LL;
constexpr int64_t SECONDS_PER_MINUTE = 60LL;
constexpr int64_t MILLISECONDS_PER_SECOND = 1000LL;
constexpr int64_t ONE_DAY_MS = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MILLISECONDS_PER_SECOND;
constexpr int64_t MAX_BASE_TIME_MS = 4102444800000LL;
constexpr int64_t MAX_JITTER_MS = 5000;
constexpr int64_t MAX_CLOSE_JITTER_MS = 50;
constexpr int64_t MAX_ELAPSED_JITTER_MS = 1000;
constexpr int64_t MAX_CERTAINTY_MS = 1000;
constexpr int64_t BOOT_TIME_DAY_COUNT = 2;
constexpr int64_t MIN_BASE_TIME_MS = 1;
constexpr size_t TRUSTED_CANDIDATE_PREFIX_COUNT = 2;
constexpr size_t MAX_CANDIDATES = 4;
constexpr size_t MAX_SERVER_LENGTH = 48;

std::string ConsumeServerName(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> servers = {
        "time1.openharmony.local", "time2.openharmony.local", "trusted.ntp.local", "", "invalid server"
    };
    if (provider.ConsumeBool()) {
        return servers[provider.ConsumeIntegralInRange<size_t>(0, servers.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_SERVER_LENGTH);
}

std::shared_ptr<MiscServices::NtpTrustedTime::TimeResult> BuildTimeResult(FuzzedDataProvider &provider,
    int64_t baseTime, int64_t baseElapsed, bool closeToBase)
{
    int64_t timeJitter = closeToBase ?
        provider.ConsumeIntegralInRange<int64_t>(-MAX_CLOSE_JITTER_MS, MAX_CLOSE_JITTER_MS) :
        provider.ConsumeIntegralInRange<int64_t>(-MAX_JITTER_MS, MAX_JITTER_MS);
    int64_t elapsedJitter = provider.ConsumeIntegralInRange<int64_t>(-MAX_ELAPSED_JITTER_MS, MAX_ELAPSED_JITTER_MS);
    int64_t certainty = provider.ConsumeIntegralInRange<int64_t>(0, MAX_CERTAINTY_MS);
    return std::make_shared<MiscServices::NtpTrustedTime::TimeResult>(baseTime + timeJitter,
        baseElapsed + elapsedJitter, certainty, ConsumeServerName(provider));
}

void ExerciseTimeResult(std::shared_ptr<MiscServices::NtpTrustedTime::TimeResult> &result,
    FuzzedDataProvider &provider)
{
    if (result == nullptr) {
        return;
    }
    int64_t bootTime = provider.ConsumeIntegralInRange<int64_t>(0, ONE_DAY_MS * BOOT_TIME_DAY_COUNT);
    (void)result->GetTimeMillis();
    (void)result->GetElapsedRealtimeMillis();
    (void)result->CurrentTimeMillis(bootTime);
    (void)result->GetAgeMillis(bootTime);
    (void)result->GetNtpServer();
    if (provider.ConsumeBool()) {
        result->Clear();
    }
}
} // namespace

void RunNtptrustedtimeStateFuzzer(FuzzedDataProvider &provider)
{
    auto &trustedTime = MiscServices::NtpTrustedTime::GetInstance();
    trustedTime.ClearTimeResultCandidates();

    int64_t baseTime = provider.ConsumeIntegralInRange<int64_t>(MIN_BASE_TIME_MS, MAX_BASE_TIME_MS);
    int64_t baseElapsed = provider.ConsumeIntegralInRange<int64_t>(MIN_BASE_TIME_MS, ONE_DAY_MS);
    if (provider.ConsumeBool()) {
        trustedTime.mTimeResult = BuildTimeResult(provider, baseTime, baseElapsed, true);
    } else {
        trustedTime.mTimeResult.reset();
    }

    size_t candidateCount = provider.ConsumeIntegralInRange<size_t>(1, MAX_CANDIDATES);
    std::vector<std::shared_ptr<MiscServices::NtpTrustedTime::TimeResult>> candidates;
    candidates.reserve(candidateCount);
    for (size_t index = 0; index < candidateCount; ++index) {
        bool closeToBase = index < TRUSTED_CANDIDATE_PREFIX_COUNT || provider.ConsumeBool();
        auto candidate = BuildTimeResult(provider, baseTime, baseElapsed, closeToBase);
        candidates.emplace_back(candidate);
        ExerciseTimeResult(candidate, provider);
        (void)trustedTime.IsTimeResultTrusted(candidate);
    }

    if (!candidates.empty()) {
        (void)trustedTime.GetSameTimeResultCount(candidates.front(), candidates);
    }
    (void)trustedTime.FindBestTimeResult();
    (void)trustedTime.GetCacheAge();
    (void)trustedTime.CurrentTimeMillis();
    (void)trustedTime.ElapsedRealtimeMillis();
    (void)trustedTime.GetBootTimeNs();

    auto emptyResult = std::make_shared<MiscServices::NtpTrustedTime::TimeResult>();
    emptyResult->Clear();
    ExerciseTimeResult(emptyResult, provider);

    trustedTime.ClearTimeResultCandidates();
    if (provider.ConsumeBool()) {
        trustedTime.mTimeResult.reset();
    }
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunNtptrustedtimeStateFuzzer(provider);
    return 0;
}
