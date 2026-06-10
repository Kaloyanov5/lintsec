package com.lintsec.crawler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.IDN;
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

    private TargetGuard() {}

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
     *  site-local (RFC1918), wildcard (0.0.0.0 / ::), and multicast. Pure — no DNS. */
    static boolean isBlockedAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress();
    }
}
