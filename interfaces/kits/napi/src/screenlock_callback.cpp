/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "screenlock_callback.h"


#include <cstdint>
#include <new>
#include <string>

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_screenlock_ability.h"
#include "node_api.h"
#include "sclock_log.h"
#include "screenlock_common.h"
#include "uv_queue.h"

namespace OHOS {
namespace ScreenLock {
ScreenlockCallback::ScreenlockCallback(const EventListener &eventListener)
{
    eventListener_ = eventListener;
}

ScreenlockCallback::~ScreenlockCallback()
{
}

void UvWorkOnCallBackInt(uv_work_t *work, int status)
{
    SCLOCK_HILOGD("UvWorkOnCallBackInt begin");
    if (work == nullptr) {
        SCLOCK_HILOGE("UvWorkNotifyMissionChanged, work is null");
        return;
    }
    ScreenlockOnCallBack *screenlockOnCallBackPtr = static_cast<ScreenlockOnCallBack *>(work->data);
    if (screenlockOnCallBackPtr == nullptr) {
        SCLOCK_HILOGE("UvWorkOnCallBackInt, screenlockOnCallBackPtr is null");
        delete work;
        return;
    }
    napi_value isResult = 0;
    int intCallbackValue = atoi(screenlockOnCallBackPtr->systemEvent.params_.c_str());
    if (screenlockOnCallBackPtr->deferred) {
        napi_get_undefined(screenlockOnCallBackPtr->env, &isResult);
        if (intCallbackValue == SCREEN_SUCC) {
            napi_resolve_deferred(screenlockOnCallBackPtr->env, screenlockOnCallBackPtr->deferred, isResult);
        } else {
            napi_reject_deferred(screenlockOnCallBackPtr->env, screenlockOnCallBackPtr->deferred, isResult);
        }
    } else {
        SCLOCK_HILOGD("ScreenlockCallback style");
        napi_value callbackFunc = nullptr;
        napi_get_reference_value(screenlockOnCallBackPtr->env, screenlockOnCallBackPtr->callbackref, &callbackFunc);
        napi_value callbackResult = nullptr;
        napi_value callBackValue[ARGS_SIZE_TWO] = { 0 };
        if (intCallbackValue == SCREEN_SUCC) {
            napi_get_undefined(screenlockOnCallBackPtr->env, &callBackValue[0]);
            napi_create_int32(screenlockOnCallBackPtr->env, static_cast<int32_t>(intCallbackValue), &callBackValue[1]);
        } else {
            const char *str = "ScreenlockCallback failed";
            napi_create_string_utf8(screenlockOnCallBackPtr->env, str, strlen(str), &callBackValue[0]);
            napi_get_undefined(screenlockOnCallBackPtr->env, &callBackValue[1]);
        }
        napi_call_function(
            screenlockOnCallBackPtr->env, nullptr, callbackFunc, ARGS_SIZE_TWO, callBackValue, &callbackResult);
    }
    if (screenlockOnCallBackPtr != nullptr) {
        delete screenlockOnCallBackPtr;
        screenlockOnCallBackPtr = nullptr;
    }
    if (work != nullptr) {
        delete work;
    }
    SCLOCK_HILOGD("UvWorkOnCallBackInt end");
}

void ScreenlockCallback::OnCallBack(const SystemEvent &systemEvent)
{
    ScreenlockOnCallBack *screenlockOnCallBack = new (std::nothrow) ScreenlockOnCallBack;
    if (screenlockOnCallBack == nullptr) {
        SCLOCK_HILOGE("new  ScreenlockOnCallBack failed");
        return;
    }
    screenlockOnCallBack->env = eventListener_.env;
    screenlockOnCallBack->callbackref = eventListener_.callbackRef;
    screenlockOnCallBack->systemEvent = systemEvent;
    screenlockOnCallBack->deferred = eventListener_.deferred;
    bool bRet = UvQueue::Call(eventListener_.env, (void *)screenlockOnCallBack, UvWorkOnCallBackInt);
    if (!bRet) {
        SCLOCK_HILOGE("ScreenlockCallback::OnCallBack faild, event=%{public}s,result=%{public}s",
            systemEvent.eventType_.c_str(), systemEvent.params_.c_str());
    }
}
} // namespace ScreenLock
} // namespace OHOS
