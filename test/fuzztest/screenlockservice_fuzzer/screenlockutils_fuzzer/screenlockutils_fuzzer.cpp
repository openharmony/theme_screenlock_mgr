/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * miscservices under the License is miscservices on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "screenlockutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "preferences_util.h"


using namespace OHOS::ScreenLock;

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr size_t LENGTH = 1;

bool FuzzScreenlockUtils(const uint8_t *rawData, size_t size)
{
    if (size < LENGTH) {
        return true;
    }
    auto preferencesUtil = DelayedSingleton<PreferencesUtil>::GetInstance();
    if (preferencesUtil == nullptr) {
        return false;
    }
    int userId = 100;

    // string
    std::string stringlVal = "test";
    preferencesUtil->SaveString(std::to_string(userId), stringlVal);
    preferencesUtil->ObtainString(std::to_string(userId), stringlVal);
    preferencesUtil->RemoveKey(std::to_string(userId));
    preferencesUtil->Refresh();

    // int
    int defaulVal = 1;
    preferencesUtil->SaveInt(std::to_string(userId), defaulVal);
    preferencesUtil->ObtainInt(std::to_string(userId), defaulVal);
    preferencesUtil->RemoveKey(std::to_string(userId));
    preferencesUtil->Refresh();

    // bool
    bool boolVal = 0;
    preferencesUtil->SaveBool(std::to_string(userId), boolVal);
    preferencesUtil->ObtainBool(std::to_string(userId), boolVal);
    preferencesUtil->RemoveKey(std::to_string(userId));
    preferencesUtil->Refresh();

    // long
    int64_t longVal = 101;
    preferencesUtil->SaveLong(std::to_string(userId), longVal);
    preferencesUtil->ObtainLong(std::to_string(userId), longVal);
    preferencesUtil->RemoveKey(std::to_string(userId));
    preferencesUtil->Refresh();

    // float
    float floatVal = 1.0;
    preferencesUtil->SaveFloat(std::to_string(userId), floatVal);
    preferencesUtil->ObtainFloat(std::to_string(userId), floatVal);
    preferencesUtil->RemoveKey(std::to_string(userId));
    preferencesUtil->Refresh();

    bool result = preferencesUtil->IsExistKey(std::to_string(userId));

    preferencesUtil->RemoveAll();
    preferencesUtil->RefreshSync();

    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzScreenlockUtils(data, size);
    return 0;
}