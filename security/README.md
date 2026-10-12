# Browser containment

The browser has only an internal Docker network. The scanner and public-only proxy are
on that network too, but only those two services have an external network route.
The API key exists only in the scanner. The browser gets no volume mounts or host ports.

The proxy validates every DNS answer as globally routable and connects directly to the
selected sockaddr. A second DNS lookup could introduce a rebinding race, so the proxy
does not use a hostname in `connect()` after validation. HTTPS remains encrypted.

This small proxy is not a general-purpose internet proxy and is not independently audited.
It does not constrain the semantics of HTTPS requests. Keep it off public networks and
use the Compose stack in a disposable VM, especially for the real challenge dataset.

The vendored `seccomp_profile.json` is based on:

https://github.com/microsoft/playwright/blob/v1.58.0/utils/docker/seccomp_profile.json

Upstream project: Microsoft Playwright, Apache-2.0 license:

https://github.com/microsoft/playwright/blob/v1.58.0/LICENSE

The namespace setup rule also allows `chroot`, which Chromium uses after entering its
user namespace. The upstream chroot rule was conditional on the container having
CAP_SYS_CHROOT; with all container capabilities dropped it blocked Chromium sandbox
startup. The project still drops all container capabilities and retains the rest of
the upstream syscall policy.
The browser sets `chromiumSandbox: true`. An unsupported host should fail closed; do not
disable the sandbox or make the container privileged as a workaround.
