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

#ifndef OHOS_QUERY_TIME_UTILS_H
#define OHOS_QUERY_TIME_UTILS_H

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>

namespace OHOS {
namespace QueryTime {

using json = nlohmann::json;

// Tool name
extern const char* TOOL_NAME;

// Log output to stdout (unified output channel)
inline void CLI_LOG(const std::string& msg)
{
    std::cout << msg << std::endl;
}

inline void CLI_ERROR(const std::string& msg)
{
    std::cout << "[ERROR] " << msg << std::endl;
}

// Success response - output JSON with type=result, status=success
int OutputSuccess(const json& data);

// Error response - output JSON with type=result, status=failed
int OutputError(const std::string& code, const std::string& message, const std::string& suggestion);

} // namespace QueryTime
} // namespace OHOS

#endif // OHOS_QUERY_TIME_UTILS_H
