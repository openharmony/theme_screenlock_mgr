/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "screenlock_inner_listener_stub.h"

#include "sclock_log.h"
#include "screenlock_common.h"

namespace OHOS {
namespace ScreenLock {
ScreenLockInnerListenerStub::~ScreenLockInnerListenerStub()
{
}

int32_t ScreenLockInnerListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        SCLOCK_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_SCREENLOCK_TRANSACT_ERROR;
    }
    switch (code) {
        case ON_LISTENER_STATE_CHANGED: {
            OnStateChangedStub(data, reply);
            break;
        }
        default: {
            return OHOS::UNKNOWN_TRANSACTION;
        }
    }
    return OHOS::NO_ERROR;
}

int32_t ScreenLockInnerListenerStub::OnStateChangedStub(MessageParcel &data, MessageParcel &reply)
{
    SCLOCK_HILOGD("OnStateChangedStub.");
    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        SCLOCK_HILOGE("failed to read userId");
        return ERR_INVALID_DATA;
    }
    int32_t state = 0;
    if (!data.ReadInt32(state)) {
        SCLOCK_HILOGE("failed to read state");
        return ERR_INVALID_DATA;
    }

    OnStateChanged(userId, state);
    return 0;
}

void ScreenLockInnerListenerStub::OnStateChanged(int32_t userId, int32_t state)
{
    SCLOCK_HILOGI("called");
    return;
}
} // namespace ScreenLock
} // namespace OHOS