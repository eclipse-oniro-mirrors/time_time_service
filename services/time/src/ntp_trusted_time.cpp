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

#include "ntp_trusted_time.h"

#include <cinttypes>

#include "sntp_client.h"

namespace OHOS {
namespace MiscServices {
namespace {
constexpr int64_t TIME_RESULT_UNINITED = -1;
constexpr int64_t HALF = 2;
constexpr int NANO_TO_SECOND =  1000000000;
constexpr int64_t ONE_DAY = 86400000;
// RTC has approximate 2s error per day
constexpr int64_t MAX_TIME_DRIFT_IN_ONE_DAY = 2000;
constexpr int64_t MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS = 100;
} // namespace

std::mutex NtpTrustedTime::mTimeResultMutex_;

NtpTrustedTime &NtpTrustedTime::GetInstance()
{
    static NtpTrustedTime instance;
    return instance;
}

bool NtpTrustedTime::ForceRefresh(const std::string &ntpServer)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    SNTPClient client;
    if (client.RequestTime(ntpServer)) {
        auto timeResult = std::make_shared<TimeResult>(client.getNtpTime(), client.getNtpTimeReference(),
            client.getRoundTripTime() / HALF);
        std::lock_guard<std::mutex> lock(mTimeResultMutex_);
        if (IsTimeResultTrusted(timeResult)) {
            return true;
        }
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "false end");
    return false;
}

// needs to acquire the lock `mTimeResultMutex_` before calling this method
bool NtpTrustedTime::IsTimeResultTrusted(std::shared_ptr<TimeResult> timeResult)
{
    // system has not got ntp time, push into candidate list
    if (mTimeResult == nullptr) {
        TimeResultCandidates_.push_back(timeResult);
        return false;
    }
    // mTimeResult is invaild, push into candidate list
    auto oldNtpTime = mTimeResult->CurrentTimeMillis(timeResult->GetElapsedRealtimeMillis());
    if (oldNtpTime == TIME_RESULT_UNINITED) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "mTimeResult time is invaild");
        TimeResultCandidates_.push_back(timeResult);
        return false;
    }
    // mTimeResult is beyond max value of kernel gap, this server is untrusted
    auto newNtpTime = timeResult->GetTimeMillis();
    if (std::abs(newNtpTime - oldNtpTime) > MAX_TIME_DRIFT_IN_ONE_DAY) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "NTP server is untrusted old:%{public}" PRId64 " new:%{public}" PRId64 "",
            oldNtpTime, newNtpTime);
        TimeResultCandidates_.push_back(timeResult);
        return false;
    }
    // cause refresh time success, old value is invaild
    TimeResultCandidates_.clear();
    mTimeResult = timeResult;
    return true;
}

int32_t NtpTrustedTime::GetSameTimeResultCount(std::shared_ptr<TimeResult> candidateTimeResult)
{
    auto candidateBootTime = candidateTimeResult->GetElapsedRealtimeMillis();
    auto candidateRealTime = candidateTimeResult->GetTimeMillis();
    int count = 0;
    for (size_t i = 0; i < TimeResultCandidates_.size(); i++) {
        auto compareTime = TimeResultCandidates_[i]->CurrentTimeMillis(candidateBootTime);
        if (std::abs(compareTime - candidateRealTime) < MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS) {
            count += 1;
        }
    }
    return count;
}

// needs to acquire the lock `mTimeResultMutex_` before calling this method
bool NtpTrustedTime::FindBestTimeResult()
{
    if (TimeResultCandidates_.size() == 0 || TimeResultCandidates_.size() == 1) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "no or one candidate");
        return false;
    }

    int32_t mostVotedTimeResultCount = 0;
    std::shared_ptr<TimeResult> mostVotedTimeResult;
    for (size_t i = 0; i < TimeResultCandidates_.size(); i++) {
        auto timeResult = TimeResultCandidates_[i];
        int32_t count = GetSameTimeResultCount(TimeResultCandidates_[i]);
        if (count > mostVotedTimeResultCount) {
            mostVotedTimeResultCount = count;
            mostVotedTimeResult = timeResult;
        }
    }

    TimeResultCandidates_.clear();
    if (mostVotedTimeResultCount == 1) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "no best candidate");
        return false;
    } else {
        mTimeResult = mostVotedTimeResult;
        return true;
    }
}

void NtpTrustedTime::ClearTimeResultCandidates()
{
    TimeResultCandidates_.clear();
}

int64_t NtpTrustedTime::CurrentTimeMillis()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    std::lock_guard<std::mutex> lock(mTimeResultMutex_);
    if (mTimeResult == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
    int64_t bootTime = 0;
    int res = TimeUtils::GetBootTimeMs(bootTime);
    if (res != E_TIME_OK) {
        return TIME_RESULT_UNINITED;
    }
    return mTimeResult->CurrentTimeMillis(bootTime);
}

int64_t NtpTrustedTime::ElapsedRealtimeMillis()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    std::lock_guard<std::mutex> lock(mTimeResultMutex_);
    if (mTimeResult == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
    return mTimeResult->GetElapsedRealtimeMillis();
}

int64_t NtpTrustedTime::GetCacheAge()
{
    std::lock_guard<std::mutex> lock(mTimeResultMutex_);
    if (mTimeResult != nullptr) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
                   .count() -
               mTimeResult->GetElapsedRealtimeMillis();
    } else {
        return INT_MAX;
    }
}

std::chrono::steady_clock::time_point NtpTrustedTime::GetBootTimeNs()
{
    int64_t timeNow = -1;
    struct timespec tv {};
    if (clock_gettime(CLOCK_BOOTTIME, &tv) < 0) {
        return std::chrono::steady_clock::now();
    }
    timeNow = tv.tv_sec * NANO_TO_SECOND + tv.tv_nsec;
    std::chrono::steady_clock::time_point tp_epoch ((std::chrono::nanoseconds(timeNow)));
    return tp_epoch;
}

int64_t NtpTrustedTime::TimeResult::GetTimeMillis()
{
    return mTimeMillis;
}

int64_t NtpTrustedTime::TimeResult::GetElapsedRealtimeMillis()
{
    return mElapsedRealtimeMillis;
}

int64_t NtpTrustedTime::TimeResult::CurrentTimeMillis(int64_t bootTime)
{
    if (mTimeMillis == 0 || mElapsedRealtimeMillis == 0) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    if (bootTime - mElapsedRealtimeMillis > ONE_DAY) {
        Clear();
        return TIME_RESULT_UNINITED;
    }
    return mTimeMillis + GetAgeMillis(bootTime);
}

int64_t NtpTrustedTime::TimeResult::GetAgeMillis(int64_t bootTime)
{
    return bootTime - this->mElapsedRealtimeMillis;
}

NtpTrustedTime::TimeResult::TimeResult()
{
}
NtpTrustedTime::TimeResult::~TimeResult()
{
}

NtpTrustedTime::TimeResult::TimeResult(int64_t mTimeMillis, int64_t mElapsedRealtimeMills, int64_t mCertaintyMillis)
{
    this->mTimeMillis = mTimeMillis;
    this->mElapsedRealtimeMillis = mElapsedRealtimeMills;
    this->mCertaintyMillis = mCertaintyMillis;
    TIME_HILOGD(TIME_MODULE_SERVICE, "mTimeMillis %{public}" PRId64 "", mTimeMillis);
    TIME_HILOGD(TIME_MODULE_SERVICE, "mElapsedRealtimeMills %{public}" PRId64 "", mElapsedRealtimeMills);
    TIME_HILOGD(TIME_MODULE_SERVICE, "mCertaintyMillis %{public}" PRId64 "", mCertaintyMillis);
}

void NtpTrustedTime::TimeResult::Clear()
{
    mTimeMillis = 0;
    mElapsedRealtimeMillis = 0;
    mCertaintyMillis = 0;
}
} // namespace MiscServices
} // namespace OHOS