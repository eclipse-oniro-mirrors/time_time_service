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

#include "timesntpdetail_fuzzer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/time.h>
#include <sys/types.h>

#include "fuzzer/FuzzedDataProvider.h"

#define private public // NOLINT
#include "sntp_client.h"
#undef private

namespace OHOS {
namespace {
constexpr size_t NTP_PACKAGE_SIZE = 48;
constexpr int MAX_NTP64_OFFSET = 40;
constexpr int MAX_NTP32_OFFSET = 44;
constexpr size_t REFERENCE_ID_SIZE = 4;
constexpr size_t BITS_PER_BYTE = 8;
constexpr uint64_t BYTE_MASK = 0xFF;
constexpr uint64_t NTP_TIMESTAMP_FRACTION_SHIFT = 32;
constexpr int TRANSMIT_TIMESTAMP_OFFSET = 32;
constexpr int DESTINATION_TIMESTAMP_OFFSET = 40;
constexpr uint16_t MAX_TIMESTAMP_DELTA = 1000;
constexpr uint32_t SECONDS_PER_DAY = 86400U;
constexpr uint32_t DAYS_PER_YEAR = 365U;
constexpr int64_t MAX_TIMEVAL_USEC = 999999;
constexpr uint64_t NTP_UNIX_EPOCH_SECONDS = 2208988800ULL;
constexpr int64_t MAX_UNIX_TIME_SECONDS = 4102444800LL;

using Packet = std::array<char, NTP_PACKAGE_SIZE>;

Packet ConsumePacket(FuzzedDataProvider &provider)
{
    Packet packet {};
    auto bytes = provider.ConsumeBytes<uint8_t>(packet.size());
    for (size_t index = 0; index < packet.size(); ++index) {
        packet[index] = index < bytes.size() ? static_cast<char>(bytes[index]) : 0;
    }
    return packet;
}

void WriteNtpTimestamp(Packet &packet, int offset, uint64_t timestamp)
{
    if (offset < 0 || static_cast<size_t>(offset + sizeof(uint64_t)) > packet.size()) {
        return;
    }
    for (size_t index = 0; index < sizeof(uint64_t); ++index) {
        uint64_t shift = (sizeof(uint64_t) - 1 - index) * BITS_PER_BYTE;
        packet[offset + index] = static_cast<char>((timestamp >> shift) & BYTE_MASK);
    }
}

uint64_t BuildValidLikeNtpTimestamp(FuzzedDataProvider &provider)
{
    uint64_t seconds = NTP_UNIX_EPOCH_SECONDS +
        provider.ConsumeIntegralInRange<uint32_t>(1, SECONDS_PER_DAY * DAYS_PER_YEAR);
    uint64_t fraction = provider.ConsumeIntegral<uint32_t>();
    return (seconds << NTP_TIMESTAMP_FRACTION_SHIFT) | fraction;
}
} // namespace

void RunTimesntpdetailFuzzer(FuzzedDataProvider &provider)
{
    MiscServices::SNTPClient client;
    auto packet = ConsumePacket(provider);

    client.SetClockOffset(provider.ConsumeIntegral<int>());
    int timestampOffset = provider.ConsumeIntegralInRange<int>(0, MAX_NTP64_OFFSET);
    (void)client.GetNtpTimestamp64(timestampOffset, packet.data(), packet.size());

    int fieldOffset = provider.ConsumeIntegralInRange<int>(0, MAX_NTP32_OFFSET);
    (void)client.GetNtpField32(fieldOffset, packet.data(), packet.size());
    int referenceId[REFERENCE_ID_SIZE] = {};
    client.GetReferenceId(fieldOffset, packet.data(), packet.size(), referenceId);

    timeval unixTime {};
    unixTime.tv_sec = static_cast<time_t>(provider.ConsumeIntegralInRange<int64_t>(0, MAX_UNIX_TIME_SECONDS));
    unixTime.tv_usec = static_cast<suseconds_t>(provider.ConsumeIntegralInRange<int64_t>(0, MAX_TIMEVAL_USEC));
    MiscServices::SNTPClient::ntp_timestamp ntpTimestamp {};
    client.ConvertUnixToNtp(&ntpTimestamp, &unixTime);

    (void)client.ConvertNtpToStamp(0);
    (void)client.ConvertNtpToStamp(NTP_UNIX_EPOCH_SECONDS << NTP_TIMESTAMP_FRACTION_SHIFT);
    (void)client.ConvertNtpToStamp(provider.ConsumeIntegral<uint64_t>());

    client.CreateMessage(packet.data());
    if (provider.ConsumeBool()) {
        uint64_t validTimestamp = BuildValidLikeNtpTimestamp(provider);
        WriteNtpTimestamp(packet, TRANSMIT_TIMESTAMP_OFFSET, validTimestamp);
        WriteNtpTimestamp(packet, DESTINATION_TIMESTAMP_OFFSET,
            validTimestamp + provider.ConsumeIntegralInRange<uint16_t>(1, MAX_TIMESTAMP_DELTA));
    }
    (void)client.ReceivedMessage(packet.data());
    auto getNtpTime = &MiscServices::SNTPClient::getNtpTime;
    auto getNtpTimeReference = &MiscServices::SNTPClient::getNtpTimeReference;
    auto getRoundTripTime = &MiscServices::SNTPClient::getRoundTripTime;
    (void)(client.*getNtpTime)();
    (void)(client.*getNtpTimeReference)();
    (void)(client.*getRoundTripTime)();

    MiscServices::SNTPClient::SNTPMessage message {};
    message.clear();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimesntpdetailFuzzer(provider);
    return 0;
}
