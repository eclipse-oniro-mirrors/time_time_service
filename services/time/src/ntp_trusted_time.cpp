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
} // namespace

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
        if (mTimeResult != nullptr) {
            mTimeResult->Clear();
        }
        int64_t ntpCertainty = client.getRoundTripTime() / HALF;
        mTimeResult = std::make_shared<TimeResult>(client.getNtpTime(), client.getNtpTimeReference(), ntpCertainty);
        TIME_HILOGD(TIME_MODULE_SERVICE, "Get Ntp time result");
        return true;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "false end");
    return false;
}

int64_t NtpTrustedTime::CurrentTimeMillis()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    if (mTimeResult == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
    return mTimeResult->CurrentTimeMillis();
}

int64_t NtpTrustedTime::ElapsedRealtimeMillis()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start");
    if (mTimeResult == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end");
    return mTimeResult->GetElapsedRealtimeMillis();
}

int64_t NtpTrustedTime::GetCacheAge()
{
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

int64_t NtpTrustedTime::TimeResult::CurrentTimeMillis()
{
    if (mTimeMillis == 0 || mElapsedRealtimeMillis == 0) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Missing authoritative time source");
        return TIME_RESULT_UNINITED;
    }
    return mTimeMillis + GetAgeMillis();
}

int64_t NtpTrustedTime::TimeResult::GetAgeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        NtpTrustedTime::GetInstance().GetBootTimeNs().time_since_epoch()).count() - this->mElapsedRealtimeMillis;
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