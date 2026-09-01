# Third-party notices

OwnTransit release evidence is generated from the exact production dependency
graph for the supported macOS and Linux artifacts. The signed release bundle's
`evidence/THIRD_PARTY_LICENSES.txt` includes the top-level license, copying,
notice and patent files shipped by the Go standard library and every linked Go
module. The generator fails closed when a production dependency is replaced,
has no authenticated module sums, or has no top-level license evidence.

The current pinned production-module inventory is:

| Component | Version | License evidence |
|---|---:|---|
| `filippo.io/age` | `v1.3.2` | BSD-3-Clause |
| `filippo.io/hpke` | `v0.4.0` | BSD-3-Clause |
| `github.com/coder/websocket` | `v1.8.15` | ISC |
| `golang.org/x/crypto` | `v0.55.0` | BSD-3-Clause and Go patent grant |
| `golang.org/x/sys` | `v0.47.0` | BSD-3-Clause and Go patent grant |

This inventory is a review aid, not a replacement for the exact upstream files
inside each release bundle. `scripts/tests/dependency-licenses.sh` proves that
the inventory matches the production graph and that release generation embeds
those upstream files. A dependency change must update this inventory and pass
that check before release.

The consolidated notices below accompany the standalone relay image. Release
evidence also preserves each upstream file independently under its original
name.

## `filippo.io/age` BSD 3-Clause license

Source: <https://github.com/FiloSottile/age/blob/v1.3.2/LICENSE>

Copyright 2019 The age Authors

Copyright 2019 Google LLC

Copyright 2022 Filippo Valsorda

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
- Neither the name of the age project nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Go Authors BSD 3-Clause license

This license applies to `filippo.io/hpke v0.4.0`, `golang.org/x/crypto
v0.55.0`, `golang.org/x/sys v0.47.0`, and the Go standard library shipped in
the release toolchain. Sources:

- <https://github.com/FiloSottile/hpke/blob/v0.4.0/LICENSE>
- <https://github.com/golang/crypto/blob/v0.55.0/LICENSE>
- <https://github.com/golang/sys/blob/v0.47.0/LICENSE>

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
- Neither the name of Google LLC nor the names of its contributors may be used
  to endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Additional Go patent grant

The exact upstream `PATENTS` files shipped by `golang.org/x/crypto` and
`golang.org/x/sys` are also preserved independently in release evidence.

Additional IP Rights Grant (Patents)

"This implementation" means the copyrightable works distributed by Google as
part of the Go project.

Google hereby grants to You a perpetual, worldwide, non-exclusive, no-charge,
royalty-free, irrevocable (except as stated in this section) patent license to
make, have made, use, offer to sell, sell, import, transfer and otherwise run,
modify and propagate the contents of this implementation of Go, where such
license applies only to those patent claims, both currently owned or controlled
by Google and acquired in the future, licensable by Google that are necessarily
infringed by this implementation of Go. This grant does not include claims that
would be infringed only as a consequence of further modification of this
implementation. If you or your agent or exclusive licensee institute or order
or agree to the institution of patent litigation against any entity (including
a cross-claim or counterclaim in a lawsuit) alleging that this implementation
of Go or any code incorporated within this implementation of Go constitutes
direct or contributory patent infringement, or inducement of patent
infringement, then any patent rights granted to you under this License for this
implementation of Go shall terminate as of the date such litigation is filed.

## `github.com/coder/websocket` ISC license

Source: <https://github.com/coder/websocket/blob/v1.8.15/LICENSE.txt>

Copyright (c) 2025 Coder

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

## BIP-39 English word list

OwnTransit includes the 2,048-word English vocabulary from BIP-39 solely as a
human comparison-code vocabulary. OwnTransit does not use the BIP-39 mnemonic,
wallet or seed-construction algorithm.

Word-list bytes (immutable upstream commit):
<https://github.com/bitcoin/bips/blob/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt>

The canonical BIP-39 specification identifies the work as MIT-licensed. That
license declaration is preserved at this independently immutable upstream
revision:
<https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0039.mediawiki>

BIP-39 authors named by that specification: Marek Palatinus, Pavol Rusnak,
Aaron Voisine and Sean Bowe.

MIT License

Copyright (c) 2013 BIP-39 authors

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
