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

#ifndef TIMER_APP_STATE_OBSERVER_H
#define TIMER_APP_STATE_OBSERVER_H

#include <functional>
#include <mutex>
#include <string>

#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"
#include "app_state_data.h"

namespace OHOS {
namespace MiscServices {

// Callback function type for app state changes
// bundleName: the bundle name of the app
// isRunning: true when app starts, false when app stops
using AppStateCallback = std::function<void(const std::string& bundleName, bool isRunning)>;

class TimerAppStateObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    static sptr<TimerAppStateObserver> GetInstance();

    // Register to observe app state changes
    // Empty bundleNames means observe all apps
    bool Register(const std::vector<std::string>& bundleNames, const AppStateCallback& callback);
    void Unregister();

    // App lifecycle callbacks
    void OnAppStarted(const AppExecFwk::AppStateData &appStateData) override;
    void OnAppStopped(const AppExecFwk::AppStateData &appStateData) override;

private:
    TimerAppStateObserver() = default;
    ~TimerAppStateObserver() override;

    sptr<AppExecFwk::IAppMgr> GetAppMgrInterface();

    // Helper function to handle app state changes
    void HandleAppStateChange(const AppExecFwk::AppStateData &appStateData, bool isRunning);

    // Reset internal state after unregister
    void ResetState();

    // Member variables
    std::mutex mutex_;
    bool isRegistered_ = false;
    AppStateCallback stateCallback_;
};

} // namespace MiscServices
} // namespace OHOS

#endif // TIMER_APP_STATE_OBSERVER_H
