package com.lintsec.crawler;

@FunctionalInterface
public interface CancellationToken {
    CancellationToken NONE = () -> false;

    boolean isCancellationRequested();
}
