# frida-universal-ssl-unpinning

A generic **Frida** script that disables Android TLS/certificate-pinning across
the most common networking stacks so you can inspect an app's HTTPS traffic with
an intercepting proxy (Burp Suite / mitmproxy).

## What it hooks
- OkHttp3 `CertificatePinner.check()` (all overloads)
- Conscrypt `TrustManagerImpl` (`checkTrustedRecursive` / `verifyChain`)
- Custom `X509TrustManager` (installs an all-trusting `SSLContext`)
- `HostnameVerifier` / OkHttp `OkHostnameVerifier`
- `TrustManagerFactory.getTrustManagers()`

## Usage
```bash
frida -U -f com.example.app -l ssl-unpinning.js --no-pause
```
> This only disables client-side trust checks. You still need a proxy and a way
> to route traffic to it (system proxy, transparent redirect, or VPN).

## ⚠️ Legal / ethical use
For **authorized** security testing, research, and education only — on devices,
emulators, and apps you own or have **explicit written permission** to test.
You are responsible for complying with all applicable laws and app terms of
service. Do not use against systems or accounts you are not permitted to test.
