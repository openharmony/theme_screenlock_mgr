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

#include "inner_listener_test.h"


namespace OHOS {
namespace ScreenLock {
void StrongAuthListenerTest::OnStrongAuthChanged(int32_t userId, int32_t authenticated)
{
    return;
}

void DeviceLockedListenerTest::OnDeviceLockStateChanged(int userId, bool isDeviceLocked)
{
    return;
}

int32_t InnerListenerIfTest::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                             MessageOption &option)
{
    return 0;
}

void InnerListenerIfTest::OnStateChanged(int32_t userId, int32_t state)
{
    return;
}
}
}