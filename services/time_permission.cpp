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

#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "bundle_mgr_proxy.h"

namespace OHOS {
namespace MiscServices {
const std::string TimePermission::SET_TIME = "ohos.permission.SET_TIME";
const std::string TimePermission::SET_TIME_ZONE = "ohos.permission.SET_TIME_ZONE";
bool TimePermission::CheckCallingPermission(const std::string &permissionName)
{
    if (permissionName.empty()) {
        TIME_HILOGE(TIME_MODULE_COMMON, "permission check failed, permission name is empty.");
        return false;
    }
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    int result = Security::AccessToken::PERMISSION_DENIED;
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        result = Security::AccessToken::PERMISSION_GRANTED;
    } else if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    } else {
        TIME_HILOGE(TIME_MODULE_COMMON, "permission check failed, callerToken:%{public}u,tokenType:%{public}d",
            callerToken, tokenType);
    }

    if (result != Security::AccessToken::PERMISSION_GRANTED) {
        TIME_HILOGE(TIME_MODULE_COMMON, "permission check failed, permission:%{public}s, callerToken:%{public}u",
            permissionName.c_str(), callerToken);
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

bool TimePermission::CheckSystemUidCallingPermission(int32_t uid)
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return true;
    }
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "GetSystemAbilityManager is null.");
        return false;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "GetSystemAbility is null.");
        return false;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(bundleMgrSa)->CheckIsSystemAppByUid(uid);
}
} // namespace MiscServices
} // namespace OHOS