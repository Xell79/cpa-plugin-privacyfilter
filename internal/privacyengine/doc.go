// Package privacyengine detects and redacts structured PII and credentials in
// UTF-8 text. Findings use byte offsets and deliberately do not retain the
// matched plaintext.
//
// The PII, contextual-secret, entropy, and post-validation logic in this
// package is derived from github.com/packyme/privacy-filter/filter at commit
// 64b8de3c2060 (2026-06-09), used under the MIT License included in LICENSE.
// The API, resource budgeting, strict TOML compatibility handling, and panic
// hardening are maintained in this repository.
package privacyengine
