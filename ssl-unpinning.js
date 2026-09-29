/*
 * frida-universal-ssl-unpinning
 * ---------------------------------------------------------------------------
 * Generic Android TLS/SSL certificate-pinning bypass for AUTHORIZED security
 * testing on devices/emulators you own or are explicitly permitted to test.
 *
 * It neutralises the trust checks used by the most common Android networking
 * stacks so you can proxy HTTPS traffic (Burp / mitmproxy) for API analysis:
 *
 *   1. OkHttp3  CertificatePinner.check(...)      (all overloads)
 *   2. Conscrypt TrustManagerImpl                 (checkTrustedRecursive / verifyChain)
 *   3. Any custom javax.net.ssl.X509TrustManager  (installs an all-trusting SSLContext)
 *   4. HostnameVerifier / OkHostnameVerifier      (verify() -> true)
 *   5. TrustManagerFactory hooks                  (returns an all-trusting manager)
 *
 * Usage:
 *   frida -U -f com.example.app -l ssl-unpinning.js --no-pause
 *   # or attach:
 *   frida -U -n "App Name" -l ssl-unpinning.js
 *
 * NOTE: This does NOT route traffic. You still need a proxy + a way to reach it
 * (system proxy, transparent redirect, or a VPN). This script only disables the
 * client-side certificate/trust verification.
 * ---------------------------------------------------------------------------
 */

'use strict';

function log(msg) {
    console.log('[ssl-unpin] ' + msg);
}

function safe(name, fn) {
    try {
        fn();
    } catch (e) {
        // Class/method not present in this app — that's fine, keep going.
        // console.log('[ssl-unpin] skip ' + name + ': ' + e);
    }
}

Java.perform(function () {
    log('starting universal unpinning...');

    // 1) OkHttp3 CertificatePinner — hook every overload of check()
    safe('okhttp3.CertificatePinner', function () {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        var overloads = CertificatePinner.check.overloads;
        overloads.forEach(function (ov) {
            ov.implementation = function () {
                log('OkHttp CertificatePinner.check() bypassed');
                return;
            };
        });
    });

    // 2) Conscrypt TrustManagerImpl (system X509 verification + NSC pins)
    safe('TrustManagerImpl.checkTrustedRecursive', function () {
        var ArrayList = Java.use('java.util.ArrayList');
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.checkTrustedRecursive.implementation = function () {
            log('TrustManagerImpl.checkTrustedRecursive() bypassed');
            return ArrayList.$new();
        };
    });
    safe('TrustManagerImpl.verifyChain', function () {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.overloads.forEach(function (ov) {
            ov.implementation = function (untrustedChain) {
                log('TrustManagerImpl.verifyChain() bypassed');
                return untrustedChain;
            };
        });
    });

    // 3) Replace the app's SSLContext with an all-trusting TrustManager
    safe('SSLContext.init', function () {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'org.frida.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var trustManagers = [TrustManager.$new()];
        var initOverload = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        );
        initOverload.implementation = function (km, tm, sr) {
            log('SSLContext.init() -> all-trusting TrustManager');
            return initOverload.call(this, km, trustManagers, sr);
        };
    });

    // 4) HostnameVerifier
    safe('HttpsURLConnection hostname verifier', function () {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function () {
            log('HttpsURLConnection.setDefaultHostnameVerifier() ignored');
        };
    });
    safe('okhttp3 OkHostnameVerifier', function () {
        var OkHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHostnameVerifier.verify.overloads.forEach(function (ov) {
            ov.implementation = function () {
                log('OkHostnameVerifier.verify() -> true');
                return true;
            };
        });
    });

    // 5) TrustManagerFactory.getTrustManagers -> all-trusting
    safe('TrustManagerFactory.getTrustManagers', function () {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        var TrustManager = Java.registerClass({
            name: 'org.frida.TrustAllManagerFactoryTM',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        TrustManagerFactory.getTrustManagers.implementation = function () {
            log('TrustManagerFactory.getTrustManagers() -> all-trusting');
            return [TrustManager.$new()];
        };
    });

    log('hooks installed.');
});
