package com.lintsec.service;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ScanCancellationRegistry {
    private final Set<Long> set = ConcurrentHashMap.newKeySet();

    public boolean request(Long scanId) {
        return set.add(scanId);
    }

    public boolean isRequested(Long scanId) {
        return set.contains(scanId);
    }

    public void clear(Long scanId) {
        set.remove(scanId);
    }
}
