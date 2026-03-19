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

#include "timer_app_state_observer.h"

#include "app_mgr_interface.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {

// =============================================================================
// Section 1: Singleton Access
// =============================================================================

sptr<TimerAppStateObserver> TimerAppStateObserver::GetInstance()
{
    static sptr<TimerAppStateObserver> instance =
        sptr<TimerAppStateObserver>(new TimerAppStateObserver());
    return instance;
}

// =============================================================================
// Section 2: Constructor / Destructor
// =============================================================================

TimerAppStateObserver::~TimerAppStateObserver()
{
    Unregister();
}

// =============================================================================
// Section 3: Registration Management
// =============================================================================

bool TimerAppStateObserver::Register(const std::vector<std::string>& bundleNames,
    const AppStateCallback& callback)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Register app state observer start.");
    // Phase 1: Check and set state under lock (critical section - no IPC)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (isRegistered_) {
            return true;
        }
        stateCallback_ = callback;
    }

    // Phase 2: IPC calls outside lock (prevents deadlock)
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppMgrInterface();
    if (!appMgr) {
        ResetState();
        return false;
    }

    // Empty bundleNames means observe all apps
    int ret = appMgr->RegisterApplicationStateObserver(this, bundleNames);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "register fail, ret = %{public}d", ret);
        ResetState();
        return false;
    }

    // Phase 3: Update state under lock
    {
        std::lock_guard<std::mutex> lock(mutex_);
        isRegistered_ = true;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Register app state observer end.");
    return true;
}

void TimerAppStateObserver::Unregister()
{
    // Phase 1: Quick check under lock
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isRegistered_) {
            return;
        }
    }

    // Phase 2: IPC call outside lock (prevents deadlock)
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppMgrInterface();
    if (appMgr) {
        appMgr->UnregisterApplicationStateObserver(this);
    }
    ResetState();
    TIME_HILOGI(TIME_MODULE_SERVICE, "Unregister done");
}

// =============================================================================
// Section 4: App Lifecycle Callbacks (Override)
// =============================================================================

void TimerAppStateObserver::OnAppStarted(const AppExecFwk::AppStateData &appStateData)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "OnAppStarted bundleName=%{public}s",
                appStateData.bundleName.c_str());
    HandleAppStateChange(appStateData, true);
}

void TimerAppStateObserver::OnAppStopped(const AppExecFwk::AppStateData &appStateData)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "OnAppStopped bundleName=%{public}s",
                appStateData.bundleName.c_str());
    HandleAppStateChange(appStateData, false);
}

// =============================================================================
// Section 5: Private Helper Methods
// =============================================================================

sptr<AppExecFwk::IAppMgr> TimerAppStateObserver::GetAppMgrInterface()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get SystemAbilityManager failed");
        return nullptr;
    }
    auto systemAbility = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (systemAbility == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get SystemAbility failed");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(systemAbility);
}

void TimerAppStateObserver::ResetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    isRegistered_ = false;
    stateCallback_ = nullptr;
}

void TimerAppStateObserver::HandleAppStateChange(
    const AppExecFwk::AppStateData &appStateData, bool isRunning)
{
    AppStateCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = stateCallback_;
    }
    if (callback) {
        callback(appStateData.bundleName, isRunning);
    }
}

} // namespace MiscServices
} // namespace OHOS
