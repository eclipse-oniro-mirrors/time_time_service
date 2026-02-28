/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef TIME_PERMISSION_H
#define TIME_PERMISSION_H

#include "time_common.h"
#include <mutex>
#include <vector>

namespace OHOS {
namespace AccountSA {
class AuthorizationClient;
}

namespace MiscServices {
// 定义一个接口，用于抽象 AuthorizationClient 的功能
class IAuthorizationClient {
public:
    virtual ~IAuthorizationClient() {}
    virtual ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized) = 0;
};

// 默认的实现，使用真实的 AuthorizationClient
class DefaultAuthorizationClient : public IAuthorizationClient {
public:
    ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized) override;
};

class TimePermission {
public:
    static const std::string setTime;
    static const std::string setTimeZone;
    static const std::string setTimePrivilege;

    static bool CheckCallingPermission(const std::string &permissionName);
    static bool CheckProxyCallingPermission();
    static bool CheckSystemUidCallingPermission(uint64_t tokenId);
    static bool CheckAuthorization(const std::string &privilege);

    // 检查是否在豁免列表中
    static bool IsExemptedBundle();

    // 用于测试的方法，允许注入自定义的 IAuthorizationClient 实现
    static void SetAuthorizationClient(std::shared_ptr<IAuthorizationClient> client);
    static void ResetAuthorizationClient();

private:
    static std::shared_ptr<IAuthorizationClient> GetAuthorizationClient();

    // 将全局静态变量改为类内静态成员
    static std::shared_ptr<IAuthorizationClient> authorizationClient_;
    static std::mutex authorizationClientMutex_;

    // 豁免的 bundle 名称列表
    static const std::vector<std::string> exemptedBundles_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TIME_PERMISSION_H