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

#include "time_permission.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "authorization_client.h"
#include "time_file_utils.h"
#include <memory>
#include <mutex>
#include <vector>

namespace OHOS {
namespace MiscServices {

ErrCode DefaultAuthorizationClient::CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized)
{
    return AccountSA::AuthorizationClient::GetInstance().CheckAuthorization(privilege, pid, isAuthorized);
}

std::shared_ptr<IAuthorizationClient> TimePermission::authorizationClient_ =
    std::make_shared<DefaultAuthorizationClient>();
std::mutex TimePermission::authorizationClientMutex_;

void TimePermission::SetAuthorizationClient(std::shared_ptr<IAuthorizationClient> client)
{
    std::lock_guard<std::mutex> lock(authorizationClientMutex_);
    authorizationClient_ = client;
}

void TimePermission::ResetAuthorizationClient()
{
    std::lock_guard<std::mutex> lock(authorizationClientMutex_);
    authorizationClient_ = std::make_shared<DefaultAuthorizationClient>();
}

std::shared_ptr<IAuthorizationClient> TimePermission::GetAuthorizationClient()
{
    std::lock_guard<std::mutex> lock(authorizationClientMutex_);
    return authorizationClient_;
}

const std::string TimePermission::setTime = "ohos.permission.SET_TIME";
const std::string TimePermission::setTimeZone = "ohos.permission.SET_TIME_ZONE";
const std::string TimePermission::setTimePrivilege = "ohos.privilege.modify_system_time";
const std::vector<std::string> TimePermission::exemptedBundles_ = {
    "telephony", "CollaborationFw", "edm", "acts", "example",
    "test", "push_manager_service", "timer"};

bool TimePermission::CheckCallingPermission(const std::string &permissionName)
{
    if (permissionName.empty()) {
        TIME_HILOGE(TIME_MODULE_COMMON, "permission check failed, permission name is empty");
        return false;
    }
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (result != Security::AccessToken::PERMISSION_GRANTED) {
        TIME_HILOGE(TIME_MODULE_COMMON, "permission check failed, result:%{public}d, permission:%{public}s",
            result, permissionName.c_str());
        return false;
    }
    return true;
}

bool TimePermission::CheckProxyCallingPermission()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    return (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
            tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL);
}

bool TimePermission::CheckSystemUidCallingPermission(uint64_t tokenId)
{
    if (CheckProxyCallingPermission()) {
        return true;
    }
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

bool TimePermission::IsExemptedBundle()
{
    std::string bundleOrProcessName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    if (bundleOrProcessName.empty()) {
        bundleOrProcessName = TimeFileUtils::GetNameByPid(IPCSkeleton::GetCallingPid());
    }
    if (bundleOrProcessName.empty()) {
        return false;
    }

    for (const auto& exempted : exemptedBundles_) {
        if (bundleOrProcessName.find(exempted) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool TimePermission::CheckAuthorization(const std::string &privilege)
{
    // 首先检查是否在豁免列表中
    if (IsExemptedBundle()) {
        return true;
    }

    int32_t pid = IPCSkeleton::GetCallingPid();
    bool isAuthorized = false;
    ErrCode err = GetAuthorizationClient()->CheckAuthorization(privilege, pid, isAuthorized);
    if (err != ERR_OK || !isAuthorized) {
        TIME_HILOGE(TIME_MODULE_COMMON,
            "CheckAuthorization failed, privilege:%{public}s, err:%{public}d, authorized:%{public}d",
            privilege.c_str(), err, isAuthorized);
        return false;
    }
    return true;
}

} // namespace MiscServices
} // namespace OHOS