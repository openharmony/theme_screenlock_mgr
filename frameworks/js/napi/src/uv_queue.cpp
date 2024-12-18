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
#include "uv_queue.h"

#include "sclock_log.h"

namespace OHOS::ScreenLock {
bool UvQueue::Call(napi_env env, ScreenlockOnCallBack *data, uv_after_work_cb afterCallback)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    if (loop == nullptr) {
        SCLOCK_HILOGE("loop == nullptr.");
        delete data;
        return false;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        SCLOCK_HILOGE("work == nullptr.");
        delete data;
        return false;
    }
    work->data = data;
    int ret = uv_queue_work_with_qos(
        loop, work, [](uv_work_t *work) {}, afterCallback, uv_qos_user_initiated);
    if (ret != 0) {
        SCLOCK_HILOGE("uv_queue_work Failed.");
        delete data;
        delete work;
        return false;
    }
    return true;
}
} // namespace OHOS::ScreenLock