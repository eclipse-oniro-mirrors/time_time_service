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


#include "timepermission_auth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "time_permission.h"

namespace OHOS {
namespace {
constexpr size_t MAX_PERMISSION_LENGTH = 64;
constexpr ErrCode AUTH_ERR_FAIL = -1;
constexpr ErrCode AUTH_ERR_RETRY = 1;
constexpr ErrCode AUTH_ERR_PERMISSION_DENIED = 201;
constexpr ErrCode AUTH_ERR_PERMISSION_MISSING = 202;
constexpr uint64_t SAMPLE_NATIVE_TOKEN_ID = 1000;
constexpr uint64_t SAMPLE_SYSTEM_TOKEN_ID = 10000;
constexpr size_t MIN_OPERATION_COUNT = 1;
constexpr size_t MAX_OPERATION_COUNT = 3;

class MockAuthorizationClient : public MiscServices::IAuthorizationClient {
public:
    MockAuthorizationClient(ErrCode errCode, bool authorized, bool flipResult)
        : errCode_(errCode), authorized_(authorized), flipResult_(flipResult)
    {
    }

    ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized) override
    {
        lastPrivilege_ = privilege;
        lastPid_ = pid;
        isAuthorized = flipResult_ ? !authorized_ : authorized_;
        callCount_++;
        return errCode_;
    }

    std::string lastPrivilege_;
    int32_t lastPid_ = 0;
    size_t callCount_ = 0;

private:
    ErrCode errCode_;
    bool authorized_;
    bool flipResult_;
};

class AuthorizationClientGuard {
public:
    explicit AuthorizationClientGuard(std::shared_ptr<MiscServices::IAuthorizationClient> client)
    {
        MiscServices::TimePermission::SetAuthorizationClient(client);
    }

    ~AuthorizationClientGuard()
    {
        MiscServices::TimePermission::ResetAuthorizationClient();
    }
};

std::string ConsumePermission(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> permissions = {
        MiscServices::TimePermission::setTime,
        MiscServices::TimePermission::setTimeZone,
        MiscServices::TimePermission::setTimePrivilege,
        "ohos.permission.SET_TIME",
        "ohos.permission.SET_TIME_ZONE",
        "ohos.permission.UNKNOWN_TIME_PERMISSION",
        "",
    };
    if (provider.ConsumeBool()) {
        return permissions[provider.ConsumeIntegralInRange<size_t>(0, permissions.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_PERMISSION_LENGTH);
}

ErrCode ConsumeErrCode(FuzzedDataProvider &provider)
{
    static const std::vector<ErrCode> errCodes = {
        ERR_OK, AUTH_ERR_FAIL, AUTH_ERR_RETRY, AUTH_ERR_PERMISSION_DENIED, AUTH_ERR_PERMISSION_MISSING
    };
    return errCodes[provider.ConsumeIntegralInRange<size_t>(0, errCodes.size() - 1)];
}

uint64_t ConsumeTokenId(FuzzedDataProvider &provider)
{
    static const std::vector<uint64_t> tokenIds = { 0, 1, SAMPLE_NATIVE_TOKEN_ID, SAMPLE_SYSTEM_TOKEN_ID, UINT64_MAX };
    if (provider.ConsumeBool()) {
        return tokenIds[provider.ConsumeIntegralInRange<size_t>(0, tokenIds.size() - 1)];
    }
    return provider.ConsumeIntegral<uint64_t>();
}
} // namespace

void RunTimepermissionAuthFuzzer(FuzzedDataProvider &provider)
{
    auto mock = std::make_shared<MockAuthorizationClient>(ConsumeErrCode(provider), provider.ConsumeBool(),
        provider.ConsumeBool());
    AuthorizationClientGuard guard(mock);

    size_t operationCount = provider.ConsumeIntegralInRange<size_t>(MIN_OPERATION_COUNT, MAX_OPERATION_COUNT);
    for (size_t index = 0; index < operationCount; ++index) {
        std::string permission = ConsumePermission(provider);
        (void)MiscServices::TimePermission::CheckCallingPermission(permission);
        (void)MiscServices::TimePermission::CheckCallingPermission("");
        (void)MiscServices::TimePermission::CheckProxyCallingPermission();
        (void)MiscServices::TimePermission::CheckSystemUidCallingPermission(ConsumeTokenId(provider));
        (void)MiscServices::TimePermission::IsAppNeedsAuthCheck();
        (void)MiscServices::TimePermission::CheckAuthorization(permission);
        bool authorized = false;
        (void)mock->CheckAuthorization(permission, provider.ConsumeIntegral<int32_t>(), authorized);
    }

    (void)MiscServices::TimePermission::CheckAuthorization(MiscServices::TimePermission::setTimePrivilege);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimepermissionAuthFuzzer(provider);
    return 0;
}
