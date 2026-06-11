package com.lintsec.crawler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.IDN;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * SSRF guard. A scan target is user-supplied and the scanner fetches it with the server's own
 * network identity, so without this gate an authenticated user could point a scan at
 * {@code http://169.254.169.254/} (cloud metadata), {@code http://localhost:8080} (this backend),
 * or any RFC1918 host and read the response back. This rejects non-http(s) schemes and any URL
 * whose host resolves to a loopback / link-local / site-local / wildcard / multicast address.
 *
 * <p>Applied at two points: once up front on the scan/login URL ({@link #isAllowed}, surfaced as a
 * 400 by the caller) and again on every fetched URL and submitted form action inside the crawl/scan
 * loops, so a target that serves an internal redirect or {@code <form action="http://10.../">} is
 * still blocked. Re-validating at fetch time (not only up front) also shrinks the DNS-rebinding
 * window: an attacker would have to flip DNS between our check and JSoup's resolve on every hop.
 */
public final class TargetGuard {

    private static final Logger log = LoggerFactory.getLogger(TargetGuard.class);

    // Dev/test escape hatch. When true, the internal-address gate is lifted so a developer can scan
    // a local target like http://localhost:8081. Set at startup from lintsec.scan.allow-private-targets
    // (default false; false under the prod profile) by TargetGuardConfig. volatile: written once on the
    // startup thread, read on scan threads.
    private static volatile boolean allowPrivateTargets = false;

    private TargetGuard() {}

    /** Set by {@link TargetGuardConfig} from configuration. See {@link #allowPrivateTargets}. */
    static void setAllowPrivateTargets(boolean value) {
        allowPrivateTargets = value;
    }

    /**
     * Whether {@code url} is a permitted scan/fetch target: a syntactically valid http(s) URL whose
     * host resolves only to public addresses. Fail-closed — any parse error, unresolvable host, or
     * blocked address returns false. DNS resolution happens here; literal IPs resolve offline.
     */
    public static boolean isAllowed(String url) {
        if (url == null || url.isBlank()) return false;

        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            return false;
        }

        String scheme = uri.getScheme();
        if (scheme == null) return false;
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) return false;

        String host = uri.getHost();
        if (host == null || host.isBlank()) return false;
        // URI.getHost() keeps brackets on IPv6 literals ("[::1]"); InetAddress wants them stripped.
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(IDN.toASCII(host));
        } catch (UnknownHostException e) {
            log.debug("target host did not resolve: {}", host);
            return false;
        } catch (Exception e) {
            return false;
        }

        // Dev escape hatch: permit internal/loopback/private targets for local scanning. Scheme, host,
        // and resolvability are still enforced above; only the internal-address gate below is lifted.
        if (allowPrivateTargets) return true;

        // Block if ANY resolved address is internal — defeats a record that mixes a public and a
        // private answer to slip past a "first address only" check.
        for (InetAddress address : addresses) {
            if (isBlockedAddress(address)) {
                log.warn("blocked SSRF target {} -> {}", host, address.getHostAddress());
                return false;
            }
        }
        return true;
    }

    /** True for addresses that must never be reachable from a scan: loopback, link-local,
     *  site-local (RFC1918), wildcard (0.0.0.0 / ::), multicast, plus special-use ranges the
     *  JDK helpers miss (IPv6 ULA, IPv4 CGNAT, benchmarking/test/reserved nets). Pure — no DNS. */
    static boolean isBlockedAddress(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] b = address.getAddress();
        if (address instanceof Inet6Address) {
            // Unique Local Addresses fc00::/7 (not classified site-local by the JDK).
            return (b[0] & 0xFE) == 0xFC;
        }

        int b0 = b[0] & 0xFF, b1 = b[1] & 0xFF, b2 = b[2] & 0xFF;
        if (b0 == 100 && (b1 & 0xC0) == 0x40) return true;          // CGNAT 100.64.0.0/10
        if (b0 == 192 && b1 == 0 && (b2 == 0 || b2 == 2)) return true; // 192.0.0.0/24, TEST-NET-1
        if (b0 == 198 && (b1 == 18 || b1 == 19)) return true;       // benchmarking 198.18.0.0/15
        if (b0 == 198 && b1 == 51 && b2 == 100) return true;        // TEST-NET-2 198.51.100.0/24
        if (b0 == 203 && b1 == 0 && b2 == 113) return true;         // TEST-NET-3 203.0.113.0/24
        if (b0 >= 240) return true;                                  // reserved 240.0.0.0/4 + 255.255.255.255
        return false;
    }
}
