/*
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

#include "ubpf_int.h"

void *ubpf_array_create(const struct ubpf_map_def *map_def);
void *ubpf_array_lookup(const struct ubpf_map *map, const void *key);
int ubpf_array_update(struct ubpf_map *map, const void *key,
                             void *value);

static const struct ubpf_map_ops ubpf_array_ops = {
        .map_lookup = ubpf_array_lookup,
        .map_update = ubpf_array_update,
        .map_delete = NULL,
        .map_add = NULL,
};
