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
#ifndef NAPI_SCREENLOCK_NOTIFY_TEST_INSTANCE_H
#define NAPI_SCREENLOCK_NOTIFY_TEST_INSTANCE_H
#include <list>

#include "screenlock_common.h"
#include "screenlock_event_list_test.h"
#include "screenlock_system_ability_stub.h"

namespace OHOS {
namespace ScreenLock {
class ScreenlockNotifyTestInstance : public ScreenLockSystemAbilityStub {
public:
    explicit ScreenlockNotifyTestInstance(const EventListenerTest &eventListener);
    virtual ~ScreenlockNotifyTestInstance();
    void OnCallBack(const SystemEvent &systemEvent) override;

private:
    EventListenerTest systemEventlistener_;
};
} // namespace ScreenLock
} // namespace OHOS
#endif //  NAPI_SCREENLOCK_NOTIFY_TEST_INSTANCE_H