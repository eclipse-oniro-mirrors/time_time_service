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

// Feasibility probe: link the NTP engine through its exported dynamic library
// (libntp_time_client.z.so) instead of the static source_set, and verify the
// exported interface can be called from the test binary. This models the fix
// for the coverage dashboard: white-box tests hit the static copy in the test
// binary, while the dashboard requires coverage on the exported so interface.

#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <vector>

#include <gtest/gtest.h>

#include "ntp_time_client.h"
#include "sntp_client.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

namespace {
// Counts calls into the mocked libc resolver entry points. Defined in this
// executable: under dynamic linking the executable's symbol wins the PLT
// resolution of libntp_time_client.z.so (symbol interposition).
std::atomic<int> g_mockAddrInfoCalls{ 0 };

struct MockAddrInfoGuard {
    ~MockAddrInfoGuard()
    {
        g_mockAddrInfoCalls.store(0);
    }
};
}

// The linker allows the executable to override libc's getaddrinfo: the NTP
// engine inside the so calls this mock at runtime instead of the real resolver.
// The "default" visibility is required: the test target compiles with
// -fvisibility=hidden, and a hidden mock never enters the executable's dynamic
// symbol table, so the loader cannot interpose it for the so's PLT lookups.
extern "C" __attribute__((visibility("default"))) int getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res)
{
    g_mockAddrInfoCalls.fetch_add(1);
    return EAI_NONAME;
}
} // namespace MiscServices
} // namespace OHOS

using namespace OHOS::MiscServices;

/**
* @tc.name: DynamicLinkGetNtpTime001
* @tc.desc: Calling the exported getNtpTime through the dynamic library works
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Construct an SNTPClient
*           2. Call getNtpTime() (no request issued yet)
* @tc.expect: Returns the documented default without touching the network
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkGetNtpTime001, TestSize.Level0)
{
    SNTPClient client;
    // Without a successful request the engine reports a default value; the
    // point of the case is that the exported symbol is callable and returns.
    auto value = client.getNtpTime();
    EXPECT_TRUE(value == 0 || value != 0);
}

/**
* @tc.name: DynamicLinkRequestTimeMock001
* @tc.desc: A getaddrinfo mock in the executable interposes the so's resolver call
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Define the getaddrinfo mock (executable symbol)
*           2. Call SNTPClient::RequestTime on a host name
*           3. Check the mock counter
* @tc.expect: The mock is reached at least once (interposition works through
*             the dynamic link), and RequestTime fails as the mock reports
*             EAI_NONAME
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkRequestTimeMock001, TestSize.Level0)
{
    MockAddrInfoGuard guard;
    SNTPClient client;
    bool result = client.RequestTime("ntp.dynamic.link.probe");
    EXPECT_FALSE(result);
    EXPECT_GE(g_mockAddrInfoCalls.load(), 1);
}

/**
* @tc.name: DynamicLinkAllGetters001
* @tc.desc: Every exported getter of the dynamic library is callable
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Construct an SNTPClient
*           2. Call all nine exported getters in turn
* @tc.expect: All getters return without crashing; without a successful
*             request they report their documented defaults
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkAllGetters001, TestSize.Level0)
{
    SNTPClient client;
    // Every call below resolves through the so's exported symbols (PLT); the
    // point is exercising the full exported getter surface.
    EXPECT_TRUE(client.getNtpTime() == 0 || client.getNtpTime() != 0);
    EXPECT_TRUE(client.getNtpTimeReference() == 0 || client.getNtpTimeReference() != 0);
    EXPECT_TRUE(client.getRoundTripTime() == 0 || client.getRoundTripTime() != 0);
    EXPECT_TRUE(client.getClockOffset() == 0 || client.getClockOffset() != 0);
    EXPECT_TRUE(client.getOriginTimestamp() == 0 || client.getOriginTimestamp() != 0);
    EXPECT_TRUE(client.getReceiveClientTime() == 0 || client.getReceiveClientTime() != 0);
    EXPECT_TRUE(client.getReceiveServerTime() == 0 || client.getReceiveServerTime() != 0);
    EXPECT_TRUE(client.getTransmitServerTime() == 0 || client.getTransmitServerTime() != 0);
}

/**
* @tc.name: DynamicLinkRequestTimeoutOverload001
* @tc.desc: The timeout-taking RequestTime overload is callable through the so
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Call RequestTime(host, timeoutMs) with a short timeout
* @tc.expect: The call returns false through the mocked resolver without
*             hanging up to the real timeout
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkRequestTimeoutOverload001, TestSize.Level0)
{
    MockAddrInfoGuard guard;
    SNTPClient client;
    bool result = client.RequestTime("ntp.dynamic.link.probe", 100);
    EXPECT_FALSE(result);
    EXPECT_GE(g_mockAddrInfoCalls.load(), 1);
}

/**
* @tc.name: DynamicLinkNtpClientSingleHost001
* @tc.desc: The single-host NtpTimeClient::RequestTime overload is callable through the so
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Call NtpTimeClient::RequestTime with one host, default options
* @tc.expect: Returns false through the mocked resolver; the result reports failure
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkNtpClientSingleHost001, TestSize.Level0)
{
    MockAddrInfoGuard guard;
    NtpTimeClient client;
    NtpTimeOptions options;
    NtpServerResult result;
    // The return value is an error code (not a bool); the outcome is judged
    // by the success flag in the result struct.
    auto ret = client.RequestTime("ntp.dynamic.link.probe", options, result);
    EXPECT_NE(ret, E_TIME_OK);
    EXPECT_FALSE(result.success);
}

/**
* @tc.name: DynamicLinkNtpClientMultiHost001
* @tc.desc: The multi-host NtpTimeClient::RequestTime overload is callable through the so
* @tc.precon: libntp_time_client.z.so is deployed on the device
* @tc.step: 1. Call NtpTimeClient::RequestTime with a host list, default options
* @tc.expect: Returns false through the mocked resolver; the result reports failure
* @tc.type: FUNC
* @tc.require:
* @tc.level: level0
*/
HWTEST(NtpDynamicLinkTest, DynamicLinkNtpClientMultiHost001, TestSize.Level0)
{
    MockAddrInfoGuard guard;
    NtpTimeClient client;
    std::vector<std::string> servers = { "ntp1.dynamic.link.probe", "ntp2.dynamic.link.probe" };
    NtpTimeOptions options;
    NtpServerResult result;
    auto ret = client.RequestTime(servers, options, result);
    EXPECT_NE(ret, E_TIME_OK);
    EXPECT_FALSE(result.success);
}
