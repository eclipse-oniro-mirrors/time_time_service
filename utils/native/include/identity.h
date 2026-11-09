/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef IDENTITY_H
#define IDENTITY_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace MiscServices {
// Caller-identity helper: GetCallingAppUid() returns the caller's app uid via the
// platform appid interface IPCSkeleton::GetCallingAppUid (@since 26.1.0);
// GetCallingBundleName() resolves the bundle name via token → bundle.
class IdentityHelper {
public:
    // Application identity.
    static int32_t GetCallingAppUid();
    // Application identity (bundleName).
    static std::string GetCallingBundleName();
};
} // namespace MiscServices
} // namespace OHOS
#endif // IDENTITY_H
