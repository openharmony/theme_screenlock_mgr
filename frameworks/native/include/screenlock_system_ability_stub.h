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

#ifndef SCREENLOCK_CALLBACK_INTERFACE_H
#define SCREENLOCK_CALLBACK_INTERFACE_H

#include <cstdint>
#include <string>

#include "iremote_stub.h"
#include "screenlock_system_ability_interface.h"
#include "visibility.h"

namespace OHOS {
namespace ScreenLock {
class ScreenLockSystemAbilityStub : public IRemoteStub<ScreenLockSystemAbilityInterface> {
public:
    SCREENLOCK_API ScreenLockSystemAbilityStub() = default;
    SCREENLOCK_API ~ScreenLockSystemAbilityStub() override;
    SCREENLOCK_API void OnCallBack(const SystemEvent &systemEvent) override;
    SCREENLOCK_API int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;
};
} // namespace ScreenLock
} // namespace OHOS
#endif // SCREENLOCK_CALLBACK_INTERFACE_H
