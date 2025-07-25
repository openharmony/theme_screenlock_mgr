/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef SCREENLOCK_INNER_LISTENER_WAPPER_H
#define SCREENLOCK_INNER_LISTENER_WAPPER_H

#include "screenlock_inner_listener.h"
#include "screenlock_inner_listener_stub.h"

namespace OHOS {
namespace ScreenLock {
class InnerListenerWrapper : public ScreenLockInnerListenerStub {
public:
    explicit InnerListenerWrapper(const sptr<InnerListener>& listener);
    virtual ~InnerListenerWrapper();
    void OnStateChanged(int userId, int state) override;

private:
    sptr<InnerListener> listener_;
};
} // namespace ScreenLock
} // namespace OHOS

#endif // SCREENLOCK_INNER_LISTENER_WAPPER_H