Cevell Confidential VM - Third-Party Software Notices & Licenses

This document contains licensing notices, attributions, and disclaimers for third-party 
software components included in the Cevell Confidential VM appliance and disk images.

The Cevell platform supervisor (cevell-node), orchestration engine (ox), and first-party 
control logic are governed by the primary LICENSE file (PolyForm Shield License 1.0.0). 

The third-party components listed below are distributed alongside Cevell as a software 
aggregate under their respective upstream open-source licenses and vendor agreements.

================================================================================
TABLE OF THIRD-PARTY COMPONENTS & GOVERNING LICENSES
================================================================================

1. Linux Kernel & In-Tree Modules (vmlinuz-aws 7.0.0-1006-aws)
   - Upstream: The Linux Foundation (https://kernel.org)
   - License: GNU General Public License v2.0 only (GPL-2.0-only)
   - System Call Clarification: As explicitly noted in the Linux kernel COPYING 
     documentation by Linus Torvalds, normal user programs using kernel services 
     via standard system calls do not fall under the heading of "derived work".

2. NVIDIA Open Kernel Modules (linux-objects-nvidia-595-open)
   - Upstream: NVIDIA Corporation & Affiliates
   - License: Dual MIT / GPL-2.0
   - Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES

3. NVIDIA Compute Runtime & GSP Firmware (libnvidia-compute, nvidia-firmware)
   - Upstream: NVIDIA Corporation (https://developer.nvidia.com)
   - License: NVIDIA Driver License Agreement (Section 1.1(d) Distribution Grant)
   - Copyright (c) 1993-2026 NVIDIA Corporation. All rights reserved.
   - Redistribution Grant: Section 1.1(d) authorizes distribution of unmodified 
     driver binaries provided for use with an OSI-approved open source kernel (Linux).

4. BusyBox
   - Upstream: Erik Andersen, Denys Vlasenko, and contributors
   - License: GNU General Public License v2.0 only (GPL-2.0-only)

5. GNU Bash & GNU Core Utilities
   - Upstream: Free Software Foundation, Inc. (https://www.gnu.org)
   - License: GNU General Public License v3.0 or later (GPL-3.0-or-later)

6. GNU C Library (glibc)
   - Upstream: Free Software Foundation, Inc.
   - License: GNU Lesser General Public License v2.1 or later (LGPL-2.1-or-later)

7. Python Runtime (python3)
   - Upstream: Python Software Foundation (https://www.python.org)
   - License: Python Software Foundation License (PSF-2.0)

8. uv (Python Package & Project Manager)
   - Upstream: Astral Software Inc.
   - License: Apache License 2.0 / MIT Dual License

9. nftables (Netfilter Firewall Utility)
   - Upstream: The Netfilter Project (https://netfilter.org)
   - License: GNU General Public License v2.0 only (GPL-2.0-only)

10. Mozilla CA Certificate Bundle (cacert)
    - Upstream: Mozilla Foundation
    - License: Mozilla Public License 2.0 (MPL-2.0)

11. Rust Runtime & Standard Library / libc Crate
    - Upstream: Rust Project Developers / libc contributors
    - License: MIT License / Apache License 2.0

12. Go Standard Library & Dependencies
    - Upstream: The Go Authors / Google LLC
    - License: BSD 3-Clause License
    - Direct Dependencies:
      * github.com/google/go-sev-guest: Apache License 2.0
      * github.com/google/go-configfs-tsm: Apache License 2.0
      * golang.org/x/crypto: BSD 3-Clause
      * golang.org/x/sys: BSD 3-Clause
      * gopkg.in/yaml.v3: MIT / Apache License 2.0
      * google.golang.org/protobuf: BSD 3-Clause

================================================================================
WRITTEN OFFER FOR SOURCE CODE (GPL & LGPL COMPONENTS)
================================================================================

For software components licensed under the GNU General Public License (GPL) and 
GNU Lesser General Public License (LGPL), Cevell provides the complete corresponding 
machine-readable source code, build recipes, and patches via our public Nix 
repository build definitions:

    https://github.com/cevell/private-ai

Because the Cevell CVM image is constructed deterministically using Nix, the 
repository definitions specify the exact upstream source tarballs, cryptographic 
hashes, and compiler instructions required to reproduce all GPL binaries.

Alternatively, you may request a copy of the corresponding source code on physical 
media or via electronic transmission by contacting:

    Cevell Compliance Team
    Email: contact@mail.cevell.com

================================================================================
THIRD-PARTY LICENSE TEXTS
================================================================================

--------------------------------------------------------------------------------
1. GNU GENERAL PUBLIC LICENSE, Version 2 (GPL-2.0)
--------------------------------------------------------------------------------
[Applies to Linux Kernel, BusyBox, nftables, and NVIDIA Open Kernel Modules]

Copyright (C) 1989, 1991 Free Software Foundation, Inc.
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

Preamble
The licenses for most software are designed to take away your freedom to share 
and change it. By contrast, the GNU General Public License is intended to guarantee 
your freedom to share and change free software--to make sure the software is free 
for all its users. This General Public License applies to most of the Free Software 
Foundation's software and to any other program whose authors commit to using it.

...

Section 2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and distribute
such modifications or work under the terms of Section 1 above, provided that
you also meet all of these conditions:
...
In addition, mere aggregation of another work not based on the Program with
the Program (or with a work based on the Program) on a volume of a storage or
distribution medium does not bring the other work under the scope of this
License.

--------------------------------------------------------------------------------
2. NVIDIA DRIVER LICENSE AGREEMENT (Redistribution Terms)
--------------------------------------------------------------------------------
[Applies to libnvidia-compute and nvidia-firmware]

Copyright (c) 1993-2026 NVIDIA Corporation. All rights reserved.

1. License.
1.1 Subject to the terms of this Agreement, NVIDIA grants you a non-exclusive, 
revocable, non-transferable and non-sublicensable license to:
...
d. Distribute the SOFTWARE provided for use with operating system kernels 
distributed under the terms of an OSI-approved open source license as listed by 
the Open Source Initiative at http://opensource.org, provided that (i) the 
binary files thereof are not modified in any way (except for uncompressing of 
compressed files) and (ii) this Agreement is provided to each SOFTWARE recipient.

--------------------------------------------------------------------------------
3. GNU LESSER GENERAL PUBLIC LICENSE, Version 2.1 (LGPL-2.1)
--------------------------------------------------------------------------------
[Applies to GNU C Library (glibc)]

Copyright (C) 1991, 1999 Free Software Foundation, Inc.
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

--------------------------------------------------------------------------------
4. GNU GENERAL PUBLIC LICENSE, Version 3 (GPL-3.0)
--------------------------------------------------------------------------------
[Applies to GNU Bash and GNU Core Utilities]

Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
Everyone is permitted to copy and distribute verbatim copies of this license 
document, but changing it is not allowed.

--------------------------------------------------------------------------------
5. MIT LICENSE
--------------------------------------------------------------------------------
[Applies to NVIDIA Open Modules, uv, Rust libc crate, yaml.v3]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

--------------------------------------------------------------------------------
6. APACHE LICENSE, Version 2.0
--------------------------------------------------------------------------------
[Applies to google/go-sev-guest, google/go-configfs-tsm, uv, Rust components]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

--------------------------------------------------------------------------------
7. BSD 3-CLAUSE LICENSE
--------------------------------------------------------------------------------
[Applies to Go Standard Library, golang.org/x/crypto, golang.org/x/sys]

Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
