jquery-1.8.3.min.js is the unmodified upstream jQuery 1.8.3 build
(sha256 61c6caebd23921741fb5ffe6603f16634fca9840c2bf56ac8201e9264d6daccf),
vendored only as a browser-test fixture for internal/scan/domxss_jquery_integration_test.go.
It is served by a local httptest page in tests and is never compiled into or
embedded in the product binary.

Why this version: jQuery 1.8.3's selector parser treats a value such as
`<img src=x onerror=...>` concatenated into `:contains(...)` as markup, which is
the operator-authorized PortSwigger lab class this slice verifies. Modern jQuery
does not, so a different version would not exercise the sink that the test is
about. jQuery is MIT-licensed; the file retains its upstream license header.
