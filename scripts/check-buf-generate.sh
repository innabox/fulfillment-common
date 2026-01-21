#!/bin/bash
#
# Copyright (c) 2025 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

# Check if buf is available - skip gracefully if not (e.g., in CI without buf)
if ! command -v buf >/dev/null 2>&1; then
    echo "buf not found, skipping check"
    echo "Note: Install buf locally to validate generated code before committing"
    echo "Installation: https://buf.build/docs/installation"
    exit 0
fi

# Run buf generate (same as CI)
buf generate

# Check if any files changed (same as CI)
git diff --exit-code
