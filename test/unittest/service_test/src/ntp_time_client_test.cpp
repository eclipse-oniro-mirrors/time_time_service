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

#include <cstring>
#include <deque>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netdb.h>
#include <netinet/in.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "ntp_time_client.h"
#include "ntp_trusted_time.h"

#define private public
#include "sntp_client.h"
#undef private

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;

// ---------------------------------------------------------------------------
// Mock network layer. SNTPClient is a plain class with no injection point, so
// the test interposes the libc/system calls it uses (getaddrinfo/socket/send/
// recv/...) within this executable.
//
// Isolation depends on the linker's default behavior plus this TU being built
// with -fvisibility=hidden (module_private_config): the mocks are hidden and
// therefore NOT exported into the executable's .dynsym, so shared libraries
// (libhilog/samgr/ipc/...) keep using the real libc instead of being
// intercepted. If that visibility setting or the symbol-interposition model
// changes (e.g. switching to --wrap), revisit this isolation claim.
// ---------------------------------------------------------------------------

// NTP seconds from 1/1/1900 to 1/1/1970 (RFC 2030), same value as sntp_client.cpp.
constexpr uint64_t SECONDS_SINCE_FIRST_EPOCH = 2208988800;
// Arbitrary fake socket fd returned by the mock.
constexpr int FAKE_SOCKET_FD = 42;
// NTP wire format constants.
constexpr int64_t MS_PER_SECOND = 1000;
constexpr size_t NTP_TS_BYTES = 8;           // an NTP timestamp is 8 bytes
constexpr size_t NTP_TS_LAST_INDEX = NTP_TS_BYTES - 1;
constexpr size_t BITS_PER_BYTE = 8;
constexpr int NTP_SERVER_PORT = 123;
constexpr int32_t NTP_RECEIVE_TS_OFFSET = 32;   // T2 offset in the response
constexpr int32_t NTP_TRANSMIT_TS_OFFSET = 40;  // T3 offset in the response
constexpr uint32_t DEFAULT_TIMEOUT_MS = 5000;   // same default as the engine

struct MockResponse {
    int64_t receiveTimeMs = 0;   // server receive time (T2), unix ms
    int64_t transmitTimeMs = 0;  // server transmit time (T3), unix ms
    bool shouldFail = false;     // simulate an unreachable/timed-out server
};

// One response per server request, consumed in order by the mock getaddrinfo.
std::deque<MockResponse> g_mockResponses;
MockResponse g_currentResponse;
bool g_hasCurrentResponse = false;

int g_getAddrInfoCalls = 0;
int g_socketCalls = 0;
int g_setTimeOfDayCalls = 0;

// Failure-injection switches for the individual network steps.
bool g_mockSocketFail = false;
bool g_mockConnectFail = false;
bool g_mockSendFail = false;
bool g_mockRecvFail = false;

// Write an NTP timestamp (seconds since 1900 << 32 | fraction) as big-endian bytes.
void WriteNtpTimestamp(char *dst, int64_t unixMs)
{
    int64_t seconds = unixMs / MS_PER_SECOND + static_cast<int64_t>(SECONDS_SINCE_FIRST_EPOCH);
    uint32_t fraction = static_cast<uint32_t>(
        ((static_cast<uint64_t>(unixMs) % MS_PER_SECOND) * 0x100000000ULL) / MS_PER_SECOND);
    uint64_t ts = (static_cast<uint64_t>(seconds) << 32) | fraction;
    for (size_t i = 0; i < NTP_TS_BYTES; i++) {
        dst[NTP_TS_LAST_INDEX - i] = static_cast<char>(ts & 0xFF);
        ts >>= BITS_PER_BYTE;
    }
}

void ResetMockState()
{
    g_mockResponses.clear();
    g_currentResponse = MockResponse{};
    g_hasCurrentResponse = false;
    g_getAddrInfoCalls = 0;
    g_socketCalls = 0;
    g_setTimeOfDayCalls = 0;
    g_mockSocketFail = false;
    g_mockConnectFail = false;
    g_mockSendFail = false;
    g_mockRecvFail = false;
}

NtpTimeOptions DefaultOptions()
{
    NtpTimeOptions options;
    options.perRequestTimeoutMs = DEFAULT_TIMEOUT_MS;
    return options;
}
} // namespace

// Interposed libc/system calls used by the engine under test.
extern "C" {
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
    g_getAddrInfoCalls++;
    if (g_mockResponses.empty()) {
        g_hasCurrentResponse = false;
        return EAI_NONAME;
    }
    g_currentResponse = g_mockResponses.front();
    g_mockResponses.pop_front();
    g_hasCurrentResponse = true;
    if (g_currentResponse.shouldFail) {
        return EAI_NONAME;
    }
    static struct addrinfo fakeAddrInfo {};
    static struct sockaddr_in fakeSockAddr {};
    fakeSockAddr.sin_family = AF_INET;
    fakeSockAddr.sin_port = htons(NTP_SERVER_PORT);
    fakeSockAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fakeAddrInfo.ai_family = AF_INET;
    fakeAddrInfo.ai_socktype = SOCK_DGRAM;
    fakeAddrInfo.ai_protocol = IPPROTO_UDP;
    fakeAddrInfo.ai_addr = reinterpret_cast<struct sockaddr *>(&fakeSockAddr);
    fakeAddrInfo.ai_addrlen = sizeof(fakeSockAddr);
    fakeAddrInfo.ai_next = nullptr;
    *res = &fakeAddrInfo;
    return 0;
}

void freeaddrinfo(struct addrinfo *res) {}

int socket(int domain, int type, int protocol)
{
    g_socketCalls++;
    return g_mockSocketFail ? -1 : FAKE_SOCKET_FD;
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return 0;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    return g_mockConnectFail ? -1 : 0;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    return g_mockSendFail ? -1 : static_cast<ssize_t>(len);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    if (!g_hasCurrentResponse) {
        return -1;
    }
    if (g_mockRecvFail) {
        return -1;
    }
    char *pkt = static_cast<char *>(buf);
    (void)memset_s(pkt, len, 0, len);
    pkt[0] = 0x1B; // leap=0, version=3, mode=3
    WriteNtpTimestamp(pkt + NTP_RECEIVE_TS_OFFSET, g_currentResponse.receiveTimeMs);  // T2
    WriteNtpTimestamp(pkt + NTP_TRANSMIT_TS_OFFSET, g_currentResponse.transmitTimeMs); // T3
    return static_cast<ssize_t>(len);
}

void fdsan_exchange_owner_tag(int fd, uint64_t expectedTag, uint64_t newTag) {}

int fdsan_close_with_tag(int fd, uint64_t tag)
{
    return 0;
}

int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
    g_setTimeOfDayCalls++;
    return 0;
}
} // extern "C"

namespace {
class NtpTimeClientTest : public testing::Test {
public:
    void SetUp() override
    {
        ResetMockState();
    }

    void TearDown() override
    {
        ResetMockState();
    }
};
} // namespace

/**
 * @tc.name: RequestTime_InvalidParams_ReturnsParamsError
 * @tc.desc: VM-5 / AC-1.5: empty list, empty string, illegal character and an
 *           over-limit list return E_TIME_PARAMETERS_INVALID with zero packets sent.
 * @tc.type: FUNC
 * @tc.require: R-5
 */
HWTEST_F(NtpTimeClientTest, RequestTime_InvalidParams_ReturnsParamsError, TestSize.Level0)
{
    NtpServerResult result;

    // Empty server list (multi-server).
    EXPECT_EQ(NtpTimeClient::RequestTime(std::vector<std::string>{}, DefaultOptions(), result),
        E_TIME_PARAMETERS_INVALID);
    // Empty server string (single-server).
    EXPECT_EQ(NtpTimeClient::RequestTime("", DefaultOptions(), result), E_TIME_PARAMETERS_INVALID);
    // Server string containing an illegal character (single-server).
    EXPECT_EQ(NtpTimeClient::RequestTime("ntp.example.com bad", DefaultOptions(), result),
        E_TIME_PARAMETERS_INVALID);
    // Over-limit list: 6 > NTP_MAX_SIZE=5.
    std::vector<std::string> sixServers = {"s1", "s2", "s3", "s4", "s5", "s6"};
    EXPECT_EQ(NtpTimeClient::RequestTime(sixServers, DefaultOptions(), result), E_TIME_PARAMETERS_INVALID);

    // No network request may have been issued.
    EXPECT_EQ(g_getAddrInfoCalls, 0);
    EXPECT_EQ(g_socketCalls, 0);
}

/**
 * @tc.name: RequestTime_SingleServer_SuccessWithResultFields
 * @tc.desc: VM-1 / AC-1.1: a legal single-server call returns 0 and fills the
 *           NtpServerResult fields (server/success/ntpTime/roundTrip/errCode).
 * @tc.type: FUNC
 * @tc.require: R-1
 */
HWTEST_F(NtpTimeClientTest, RequestTime_SingleServer_SuccessWithResultFields, TestSize.Level0)
{
    // Server receive (T2) at 1700000040ms, transmit (T3) at 1700000000ms.
    g_mockResponses.push_back({1700000040, 1700000000, false});
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime("ntp.example.com", DefaultOptions(), result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "ntp.example.com");
    EXPECT_EQ(result.errCode, E_TIME_OK);
    EXPECT_NE(result.clockOffsetMs, 0);
    // ntpTime ~= (T2+T3)/2; roundTripTime ~= T2-T3 (see sntp_client.cpp formulas).
    EXPECT_NEAR(result.ntpTimeMillis, (1700000040LL + 1700000000LL) / 2, 50);
    EXPECT_NEAR(result.roundTripTimeMs, 1700000040LL - 1700000000LL, 20);
    // VM-6: the engine never writes the system clock.
    EXPECT_EQ(g_setTimeOfDayCalls, 0);
}

/**
 * @tc.name: RequestTime_PartialFail_ReturnsFirstSuccessCandidate
 * @tc.desc: VM-2 / AC-1.2: when some servers fail, the call still returns 0 and
 *           the result is the first successful candidate.
 * @tc.type: FUNC
 * @tc.require: R-2
 */
HWTEST_F(NtpTimeClientTest, RequestTime_PartialFail_ReturnsFirstSuccessCandidate, TestSize.Level0)
{
    g_mockResponses.push_back({0, 0, true});          // s1 unreachable
    g_mockResponses.push_back({1700000040, 1700000000, false}); // s2 succeeds
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::FIRST_SUCCESS;
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(std::vector<std::string>{"s1", "s2"}, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s2");
}

/**
 * @tc.name: RequestTime_FirstSuccess_PicksFirstSuccessful
 * @tc.desc: VM-3 / AC-1.3: FIRST_SUCCESS returns the first successful candidate.
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_FirstSuccess_PicksFirstSuccessful, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false}); // s1
    g_mockResponses.push_back({1700001010, 1700001000, false}); // s2
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::FIRST_SUCCESS;
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(std::vector<std::string>{"s1", "s2"}, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s1");
}

/**
 * @tc.name: RequestTime_MinRtt_PicksFastestCandidate
 * @tc.desc: VM-3 / AC-1.3: MIN_RTT returns the successful candidate with the
 *           smallest round-trip time (s2 has RTT ~10ms vs s1 ~40ms).
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_MinRtt_PicksFastestCandidate, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false}); // s1 RTT ~40ms
    g_mockResponses.push_back({1700001010, 1700001000, false}); // s2 RTT ~10ms
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::MIN_RTT;
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(std::vector<std::string>{"s1", "s2"}, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s2");
}

/**
 * @tc.name: RequestTime_Vote_SelectsMajorityWithBestRtt
 * @tc.desc: VM-3 / AC-1.3: VOTE is a pure calibration vote. s1/s2/s3 form one
 *           cluster (offsets within 100ms), s4 is a far cluster and is excluded;
 *           among the majority cluster the best RTT wins (s2).
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_Vote_SelectsMajorityWithBestRtt, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false}); // s1 offset ~1700000020, RTT ~40
    g_mockResponses.push_back({1700000010, 1700000000, false}); // s2 offset ~1700000005, RTT ~10
    g_mockResponses.push_back({1700000030, 1700000000, false}); // s3 offset ~1700000015, RTT ~30
    g_mockResponses.push_back({1700002000, 1700001000, false}); // s4 far cluster, excluded
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::VOTE;
    NtpServerResult result;
    std::vector<std::string> servers = {"s1", "s2", "s3", "s4"};

    EXPECT_EQ(NtpTimeClient::RequestTime(servers, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s2");
    EXPECT_EQ(g_setTimeOfDayCalls, 0);
}

/**
 * @tc.name: RequestTime_AllServersFail_ReturnsNtpUpdateFailed
 * @tc.desc: VM-4 / AC-1.4: when every server is unreachable the call returns
 *           E_TIME_NTP_UPDATE_FAILED with no side effects.
 * @tc.type: FUNC
 * @tc.require: R-4
 */
HWTEST_F(NtpTimeClientTest, RequestTime_AllServersFail_ReturnsNtpUpdateFailed, TestSize.Level0)
{
    g_mockResponses.push_back({0, 0, true});
    g_mockResponses.push_back({0, 0, true});
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::FIRST_SUCCESS;
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(std::vector<std::string>{"s1", "s2"}, options, result),
        E_TIME_NTP_UPDATE_FAILED);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.errCode, E_TIME_NTP_UPDATE_FAILED);
    // VM-6: no clock write even on the failure path.
    EXPECT_EQ(g_setTimeOfDayCalls, 0);
}

/**
 * @tc.name: SntpClient_RequestTime_CapturesNtpReportValues
 * @tc.desc: INV-5: after a successful request, the engine exposes the four NTP
 *           timestamps the SA-side NTP_REFRESH equivalent report consumes.
 * @tc.type: FUNC
 * @tc.require: ADR-1 / ADR-5
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_CapturesNtpReportValues, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    SNTPClient client;

    EXPECT_TRUE(client.RequestTime("ntp.example.com"));
    EXPECT_NEAR(client.getReceiveServerTime(), 1700000040, 20);
    EXPECT_NEAR(client.getTransmitServerTime(), 1700000000, 20);
    EXPECT_NEAR(client.getNtpTime(), (1700000040LL + 1700000000LL) / 2, 50);
    EXPECT_NEAR(client.getRoundTripTime(), 1700000040LL - 1700000000LL, 20);
}

// ---------------------------------------------------------------------------
// Additional branch coverage: NtpTimeClient (ntp_time_client.cpp)
// ---------------------------------------------------------------------------

/**
 * @tc.name: RequestTime_SingleServerFail_ReturnsNtpUpdateFailed
 * @tc.desc: VM-4 / AC-1.4: a single-server request failing returns E_TIME_NTP_UPDATE_FAILED.
 * @tc.type: FUNC
 * @tc.require: R-4
 */
HWTEST_F(NtpTimeClientTest, RequestTime_SingleServerFail_ReturnsNtpUpdateFailed, TestSize.Level0)
{
    g_mockResponses.push_back({0, 0, true});
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime("ntp.example.com", DefaultOptions(), result), E_TIME_NTP_UPDATE_FAILED);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.errCode, E_TIME_NTP_UPDATE_FAILED);
}

/**
 * @tc.name: RequestTime_InvalidStrategy_ReturnsParamsError
 * @tc.desc: AC-1.3 boundary: an out-of-range strategy hits the switch default
 *           and returns E_TIME_PARAMETERS_INVALID after a successful request.
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_InvalidStrategy_ReturnsParamsError, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    NtpTimeOptions options = DefaultOptions();
    options.strategy = static_cast<NtpSyncStrategy>(99); // out-of-range
    NtpServerResult result;
    std::vector<std::string> servers = {"s1"};

    EXPECT_EQ(NtpTimeClient::RequestTime(servers, options, result), E_TIME_PARAMETERS_INVALID);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.errCode, E_TIME_PARAMETERS_INVALID);
}

/**
 * @tc.name: RequestTime_Vote_SingleCandidate_ReturnsDirectly
 * @tc.desc: VM-3 / AC-1.3: with only one successful candidate VOTE returns it directly.
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_Vote_SingleCandidate_ReturnsDirectly, TestSize.Level0)
{
    g_mockResponses.push_back({0, 0, true});                   // s1 fails
    g_mockResponses.push_back({1700000040, 1700000000, false}); // s2 succeeds
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::VOTE;
    NtpServerResult result;
    std::vector<std::string> servers = {"s1", "s2"};

    EXPECT_EQ(NtpTimeClient::RequestTime(servers, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s2");
}

/**
 * @tc.name: RequestTime_Vote_NoMajority_FallsBackToMinRtt
 * @tc.desc: VM-3 / AC-1.3: candidates more than 100ms apart form no majority
 *           cluster, so VOTE falls back to the fastest candidate.
 * @tc.type: FUNC
 * @tc.require: R-3
 */
HWTEST_F(NtpTimeClientTest, RequestTime_Vote_NoMajority_FallsBackToMinRtt, TestSize.Level0)
{
    // s1 offset ~1700000020 rtt 40ms; s2 offset ~1700001010 rtt 20ms (>100ms apart).
    g_mockResponses.push_back({1700000040, 1700000000, false});
    g_mockResponses.push_back({1700001020, 1700001000, false});
    NtpTimeOptions options = DefaultOptions();
    options.strategy = NtpSyncStrategy::VOTE;
    NtpServerResult result;
    std::vector<std::string> servers = {"s1", "s2"};

    EXPECT_EQ(NtpTimeClient::RequestTime(servers, options, result), E_TIME_OK);
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.server, "s2");
}

/**
 * @tc.name: RequestTime_OverlongServer_ReturnsParamsError
 * @tc.desc: VM-5 / AC-1.5: a server string longer than 255 chars is rejected
 *           without any network request.
 * @tc.type: FUNC
 * @tc.require: R-5
 */
HWTEST_F(NtpTimeClientTest, RequestTime_OverlongServer_ReturnsParamsError, TestSize.Level0)
{
    std::string overlong(256, 'a');
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(overlong, DefaultOptions(), result), E_TIME_PARAMETERS_INVALID);
    EXPECT_EQ(g_getAddrInfoCalls, 0);
}

/**
 * @tc.name: RequestTime_ControlCharServer_ReturnsParamsError
 * @tc.desc: VM-5 / AC-1.5: a server string containing a control character is
 *           rejected without any network request.
 * @tc.type: FUNC
 * @tc.require: R-5
 */
HWTEST_F(NtpTimeClientTest, RequestTime_ControlCharServer_ReturnsParamsError, TestSize.Level0)
{
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime("ntp.example.com\n", DefaultOptions(), result), E_TIME_PARAMETERS_INVALID);
    EXPECT_EQ(g_getAddrInfoCalls, 0);
}

// ---------------------------------------------------------------------------
// Additional branch coverage: SNTPClient (sntp_client.cpp)
// ---------------------------------------------------------------------------

/**
 * @tc.name: SntpClient_RequestTime_EmptyOrOverlongHost_Fails
 * @tc.desc: SNTPClient-level validation: empty or >255 char host returns false.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_EmptyOrOverlongHost_Fails, TestSize.Level0)
{
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime(""));
    EXPECT_FALSE(client.RequestTime(std::string(256, 'a')));
}

/**
 * @tc.name: SntpClient_RequestTime_InvalidResponse_Fails
 * @tc.desc: A response with zero receive/transmit timestamps is rejected by
 *           ReceivedMessage and the request fails.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_InvalidResponse_Fails, TestSize.Level0)
{
    g_mockResponses.push_back({0, 0, false});
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime("ntp.example.com"));
}

/**
 * @tc.name: SntpClient_RequestTime_SocketCreateFail_Fails
 * @tc.desc: socket() failure makes the connected-socket creation fail.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_SocketCreateFail_Fails, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    g_mockSocketFail = true;
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime("ntp.example.com"));
}

/**
 * @tc.name: SntpClient_RequestTime_ConnectFail_Fails
 * @tc.desc: connect() failure makes the request fail.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_ConnectFail_Fails, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    g_mockConnectFail = true;
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime("ntp.example.com"));
}

/**
 * @tc.name: SntpClient_RequestTime_SendFail_Fails
 * @tc.desc: send() failure makes the request fail.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_SendFail_Fails, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    g_mockSendFail = true;
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime("ntp.example.com"));
}

/**
 * @tc.name: SntpClient_RequestTime_RecvTimeout_Fails
 * @tc.desc: VM-4 / AC-1.4: recv() timing out (no reply) makes the request fail.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_RequestTime_RecvTimeout_Fails, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    g_mockRecvFail = true;
    SNTPClient client;

    EXPECT_FALSE(client.RequestTime("ntp.example.com"));
}

// ---------------------------------------------------------------------------
// SA-side NTP_REFRESH equivalent report (ntp_trusted_time.cpp
// ReportNtpRefreshEvent), triggered through NtpTrustedTime with the same
// mocked network layer.
// ---------------------------------------------------------------------------

/**
 * @tc.name: NtpTrustedTime_ForceRefresh_SuccessReportsNtpRefreshEvent
 * @tc.desc: INV-5: a successful ForceRefreshTrusted/ForceRefresh executes the
 *           NTP_REFRESH report helper and returns success (result trusted).
 * @tc.type: FUNC
 * @tc.require: ADR-5 / INV-5
 */
HWTEST_F(NtpTimeClientTest, NtpTrustedTime_ForceRefresh_SuccessReportsNtpRefreshEvent, TestSize.Level0)
{
    g_mockResponses.push_back({1700000040, 1700000000, false});
    EXPECT_TRUE(NtpTrustedTime::GetInstance().ForceRefreshTrusted("ntp.example.com"));

    g_mockResponses.push_back({1700000040, 1700000000, false});
    EXPECT_TRUE(NtpTrustedTime::GetInstance().ForceRefresh("ntp.example.com"));
}

/**
 * @tc.name: RequestTime_L2ListWithInvalidServer_ReturnsParamsError
 * @tc.desc: VM-5 / AC-1.5: a list whose size is valid but that contains one
 *           illegal server is rejected before any network request.
 * @tc.type: FUNC
 * @tc.require: R-5
 */
HWTEST_F(NtpTimeClientTest, RequestTime_L2ListWithInvalidServer_ReturnsParamsError, TestSize.Level0)
{
    std::vector<std::string> servers = {"ntp.example.com", "bad server"};
    NtpServerResult result;

    EXPECT_EQ(NtpTimeClient::RequestTime(servers, DefaultOptions(), result), E_TIME_PARAMETERS_INVALID);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(g_getAddrInfoCalls, 0);
}

/**
 * @tc.name: SntpClient_InvalidOffsets_ReturnZero
 * @tc.desc: The offset bounds checks in the timestamp/field parsers return 0
 *           (or no-op) instead of reading out of range.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_InvalidOffsets_ReturnZero, TestSize.Level0)
{
    SNTPClient client;
    char buf[48] = {0};
    int refId[4] = {0};

    // Negative and past-the-end offsets.
    EXPECT_EQ(client.GetNtpTimestamp64(-1, buf, sizeof(buf)), 0);
    EXPECT_EQ(client.GetNtpTimestamp64(static_cast<int>(sizeof(buf)), buf, sizeof(buf)), 0);
    EXPECT_EQ(client.GetNtpField32(-1, buf, sizeof(buf)), 0);
    EXPECT_EQ(client.GetNtpField32(static_cast<int>(sizeof(buf)), buf, sizeof(buf)), 0);
    client.GetReferenceId(-1, buf, sizeof(buf), refId);
    client.GetReferenceId(static_cast<int>(sizeof(buf)), buf, sizeof(buf), refId);
}

/**
 * @tc.name: SntpClient_ConvertUnixToNtp_NegativeTime_Zeroes
 * @tc.desc: A pre-1970 (negative tv_sec) input must not wrap; the NTP
 *           timestamp is zeroed out.
 * @tc.type: FUNC
 */
HWTEST_F(NtpTimeClientTest, SntpClient_ConvertUnixToNtp_NegativeTime_Zeroes, TestSize.Level0)
{
    SNTPClient client;
    SNTPClient::ntp_timestamp ntp{};
    struct timeval tv;
    tv.tv_sec = -1;
    tv.tv_usec = 0;

    client.ConvertUnixToNtp(&ntp, &tv);
    EXPECT_EQ(ntp.second, 0);
    EXPECT_EQ(ntp.fraction, 0);
}
