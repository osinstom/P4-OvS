/*
 * Copyright (c) 2008-2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef P4RT_OBJECTS_H
#define P4RT_OBJECTS_H 1

#include "openvswitch/list.h"

struct p4rtutil_table_entry {
    struct ovs_list list_node;
    uint64_t handle_id;
    uint32_t priority;
    bool is_default;
    uint32_t table_id;
    uint32_t action_id;
    const char *match_key;
    size_t key_size;
    char *action_data;
    size_t data_size;
};

#endif  /* p4rt-objects.h */
