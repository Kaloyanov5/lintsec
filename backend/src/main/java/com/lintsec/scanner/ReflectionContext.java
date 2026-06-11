package com.lintsec.scanner;

/** Where a reflected canary lands in the response, determining the breakout payload to confirm with. */
public enum ReflectionContext {
    HTML_TEXT,
    ATTR_DOUBLE,
    ATTR_SINGLE,
    ATTR_UNQUOTED,
    ATTR_URL,
    SCRIPT,
    STYLE,
    COMMENT,
    TAG_NAME,
    UNKNOWN
}
