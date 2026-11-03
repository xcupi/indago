// Copyright (c) 2026. AngularJS 1.2.32 is vendored here, unmodified, as a
// browser-test fixture for internal/scan/domxss_angular_integration_test.go
// (sha256 0215039460580e3737d7db4b114f222aeb445ea830413d192333615409ec7691).
//
// Why this version: it is the last AngularJS line with the expression sandbox
// still present, which is the PortSwigger lab class this slice targets ("DOM
// XSS in AngularJS expression execution", "Reflected XSS with AngularJS
// sandbox escape ..."). Detection never attempts a sandbox escape; the fixture
// only needs real interpolation, real `new Function`-based $parse (so a
// script-src without 'unsafe-eval' really blocks compilation) and real text-node
// writes. The file is served by a local httptest page and is never compiled
// into or embedded in the product binary. AngularJS is MIT-licensed and the
// file retains its upstream license header.
