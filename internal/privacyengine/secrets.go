package privacyengine

// Secret detection in this file is derived from
// packyme/privacy-filter/filter/secrets.go at commit 64b8de3c2060. See LICENSE
// in this directory. Bounds checks and overlap handling differ intentionally to
// fix rheodev/cpa-plugin-privacyfilter issue #3.

import (
	"context"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	entropyMin              = 4.0
	entropyMinStrict        = 4.8
	contextLookback         = 30 // bytes
	contextOverlapLookahead = 64 // bytes into a candidate
)

// Context values shorter than 8 bytes are ordinary words next to a keyword,
// not credentials. Chinese keywords stay beside the English ones so a secret
// written as "密码=..." is still detected. They are match text, not UI copy.
var reContextSecret = regexp.MustCompile(
	`(?i)(?:PASSWORD|PASSWD|SECRET|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|ENCRYPTION_KEY|SIGNING_KEY|DB_PASSWORD|DATABASE_PASSWORD|密码|口令|密钥)\s*[=:：]\s*['"]?([^\s'"，。；;]{8,})`)

var reSecretContext = regexp.MustCompile(
	`(?i)(?:password|passwd|pwd|secret|token|api[_\s-]?key|access[_\s-]?key|bearer|authorization|credential|jwt|密码|口令|密钥|凭证|令牌|鉴权)`)

const (
	pathBoundaryChars = `/\:.@?=`
	pathInternalChars = `/\:`
	assignmentChars   = " \t\r\n=:'\""
)

var urlPrefixes = []string{
	"http://", "https://", "ftp://", "ssh://",
	"s3://", "gs://", "oss://",
	"git@", "sha256:", "sha1:", "md5:",
}

var (
	reTemplateVar           = regexp.MustCompile(`^(?:\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}|\$\{\{\s*(?i:secrets)\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$\([A-Za-z_][A-Za-z0-9_]*\)|%\{[A-Za-z_][A-Za-z0-9_]*\}|<[A-Za-z_][A-Za-z0-9_]*>)$`)
	reSimpleVar             = regexp.MustCompile(`(?i)^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$env:[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$`)
	reCredentialPlaceholder = regexp.MustCompile(`(?i)^(?:(?:redacted|masked|hidden)(?:#[0-9]+)?|\[(?:redacted|masked|hidden|secret|credential|api[_ -]?key|e-?mail|phone|id(?:_card)?|card|bank_card|ip(?:_address)?|邮箱|电话|身份证|银行卡|密钥)(?:#\d+)?\])$`)
	reMaskOnly              = regexp.MustCompile(`^[*xX._-]{3,}$`)
	reUUID                  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reHexOnly               = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

var benignIDSuffixes = []string{"_id", "_uuid", "_uid", "_oid", "_no", "_seq"}

var reAuthHeaderPrefix = regexp.MustCompile(
	`(?i)\bauthorization\s*:\s*(?:basic|bearer|digest|ntlm|hmac|token)\s+$`)

var reHostPortPrefix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9-]+:`)

var commonPlaceholders = []string{
	"REPLACE_ME", "REPLACE_THIS", "REPLACE_WITH",
	"YOUR_KEY", "YOUR_TOKEN", "YOUR_SECRET", "YOUR_API_KEY", "YOUR_PASSWORD",
	"INSERT_HERE", "INSERT_KEY", "INSERT_TOKEN",
	"PLACEHOLDER", "EXAMPLE_KEY", "EXAMPLE_TOKEN",
	"TODO", "FIXME", "XXXX",
}

func (e *Engine) detectSecrets(ctx context.Context, text string, collector *spanCollector) error {
	lowerText := text
	if hasASCIIUpper(text) {
		lowerText = strings.ToLower(text)
	}
	for i := range e.rules {
		if err := ctx.Err(); err != nil {
			return err
		}
		rule := &e.rules[i]
		if !ruleApplies(rule, lowerText) {
			continue
		}
		err := forEachSubmatchIndex(ctx, rule.re, text, func(indices []int) error {
			if len(indices) < 2 || indices[0] < 0 || indices[1] < indices[0] || indices[1] > len(text) {
				return nil
			}
			matchStart, matchEnd := indices[0], indices[1]
			start, end := matchStart, matchEnd
			if rule.automaticCapture {
				// Gitleaks selects the first participating capture when
				// secretGroup is omitted, otherwise it retains the full match.
				for groupIndex := 2; groupIndex+1 < len(indices); groupIndex += 2 {
					if indices[groupIndex] >= 0 && indices[groupIndex+1] > indices[groupIndex] {
						start, end = indices[groupIndex], indices[groupIndex+1]
						break
					}
				}
			} else if rule.secretGroup > 0 {
				groupIndex := 2 * rule.secretGroup
				if groupIndex < 0 || groupIndex+1 >= len(indices) {
					return nil
				}
				start, end = indices[groupIndex], indices[groupIndex+1]
			}
			// An explicit optional capture that did not participate is not a
			// license to fall back to the full match.
			if start < 0 || start >= end || end > len(text) {
				return nil
			}
			candidate := text[start:end]
			if rule.entropy > 0 && shannonEntropy(candidate) <= rule.entropy {
				return nil
			}
			allowCandidate := allowlistCandidate{
				secret: candidate,
				match:  text[matchStart:matchEnd],
				line:   lineContaining(text, matchStart, matchEnd),
			}
			if anyAllowlisted(e.globalAllowlists, allowCandidate) || anyAllowlisted(rule.allowlists, allowCandidate) {
				return nil
			}
			if looksLikeURLMatch(candidate) || isTemplateVar(candidate) || isHexHash(candidate) ||
				isUUID(candidate) || isBusinessIDAssignment(candidate) ||
				isLikelyPlaceholder(candidate) || hasJSONNoise(candidate) {
				return nil
			}
			return collector.add(span{start: start, end: end, kind: KindSecret, ruleID: rule.id})
		})
		if err != nil {
			return err
		}
	}

	if err := forEachSubmatchIndex(ctx, reContextSecret, text, func(indices []int) error {
		if len(indices) < 4 || indices[2] < 0 || indices[3] <= indices[2] || indices[3] > len(text) {
			return nil
		}
		value := text[indices[2]:indices[3]]
		if isContextSecretNoise(value) {
			return nil
		}
		return collector.add(span{start: indices[2], end: indices[3], kind: KindSecret, ruleID: ruleContextSecret})
	}); err != nil {
		return err
	}

	return forEachEntropyToken(ctx, text, func(start, end int) error {
		candidate := text[start:end]
		strong := hasStrongSecretContext(text, start, end)
		if isFilesystemPath(candidate) || (!strong && isOnPathOrURLBoundary(text, start, end)) {
			return nil
		}
		if isTemplateVar(candidate) || isHexHash(candidate) || isUUID(candidate) || isBusinessIDAssignment(candidate) {
			return nil
		}
		threshold := entropyMin
		if !hasSecretContext(text, start, end) {
			threshold = entropyMinStrict
		}
		if shannonEntropy(candidate) < threshold {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindSecret, ruleID: ruleHighEntropy})
	})
}

func detectCredentialField(text string, collector *spanCollector, fieldContext FieldContext) error {
	if !credentialFieldApplies(fieldContext) || isCredentialPlaceholder(text) {
		return nil
	}
	return collector.add(span{
		start:  0,
		end:    len(text),
		kind:   KindSecret,
		ruleID: ruleCredentialField,
	})
}

func credentialFieldApplies(fieldContext FieldContext) bool {
	if !fieldContext.Structured ||
		(fieldContext.ToolScope != ToolScopeInput && fieldContext.ToolScope != ToolScopeOutput) {
		return false
	}
	if isCredentialFieldKey(fieldContext.ImmediateKey) {
		return true
	}
	count := int(fieldContext.AncestorCount)
	if count > len(fieldContext.Ancestors) {
		count = len(fieldContext.Ancestors)
	}
	for i := 0; i < count; i++ {
		if isCredentialAncestorFieldKey(fieldContext.Ancestors[i]) {
			return true
		}
	}
	return false
}

// CredentialFieldApplies reports whether the bounded structured context selects
// whole-value credential redaction. The abbreviated AK and SK names apply only
// as immediate keys because they are common non-credential container fields.
func CredentialFieldApplies(fieldContext FieldContext) bool {
	return credentialFieldApplies(fieldContext)
}

func isCredentialFieldKey(key string) bool {
	switch normalizeCredentialFieldKey(key) {
	case "ak", "sk", "api_key", "apikey", "api_secret", "apisecret",
		"api_secret_key", "apisecretkey",
		"access_key", "accesskey", "access_key_id", "accesskeyid",
		"secret_key", "secretkey", "secret_access_key", "secretaccesskey",
		"aws_access_key_id", "awsaccesskeyid", "aws_secret_access_key", "awssecretaccesskey",
		"client_secret", "clientsecret", "private_key", "privatekey",
		"token", "access_token", "accesstoken", "api_token", "apitoken",
		"auth_token", "authtoken", "refresh_token", "refreshtoken",
		"session_token", "sessiontoken", "id_token", "idtoken",
		"client_token", "clienttoken", "secret_token", "secrettoken",
		"bearer_token", "bearertoken", "oauth_token", "oauthtoken",
		"password", "passwd", "pwd", "credential", "secret", "secrets", "authorization":
		return true
	default:
		return false
	}
}

func isCredentialAncestorFieldKey(key string) bool {
	normalized := normalizeCredentialFieldKey(key)
	return normalized != "ak" && normalized != "sk" && isCredentialFieldKey(normalized)
}

// IsCredentialFieldKey reports whether key is an exact high-confidence
// immediate credential field name after the engine's bounded normalization.
func IsCredentialFieldKey(key string) bool {
	return isCredentialFieldKey(key)
}

// IsCredentialAncestorFieldKey reports whether key is sufficiently unambiguous
// to propagate whole-value credential handling to descendant strings.
func IsCredentialAncestorFieldKey(key string) bool {
	return isCredentialAncestorFieldKey(key)
}

func normalizeCredentialFieldKey(key string) string {
	if key == "" || len(key) > 64 {
		return ""
	}
	changed := false
	for index := 0; index < len(key); index++ {
		char := key[index]
		switch {
		case char >= 'A' && char <= 'Z', char == '-':
			changed = true
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '_':
		default:
			return ""
		}
	}
	if !changed {
		return key
	}
	var normalized strings.Builder
	normalized.Grow(len(key))
	for index := 0; index < len(key); index++ {
		char := key[index]
		switch {
		case char >= 'A' && char <= 'Z':
			normalized.WriteByte(char + ('a' - 'A'))
		case char == '-':
			normalized.WriteByte('_')
		default:
			normalized.WriteByte(char)
		}
	}
	return normalized.String()
}

func isContextSecretNoise(value string) bool {
	if isCredentialPlaceholder(value) || isTemplateVar(value) || strings.Contains(value, "${") {
		return true
	}
	if len(value) <= 16 && shannonEntropy(value) < 3.0 {
		return true
	}
	// A keyword mention of a short code identifier is not a secret value.
	if len(value) <= 24 && strings.ContainsAny(value, "()[]{}") {
		return true
	}
	return false
}

func isFilesystemPath(value string) bool {
	if strings.Count(value, "/") < 2 {
		return false
	}
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../")
}

func isCredentialPlaceholder(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" ||
		isTemplateVar(trimmed) ||
		reSimpleVar.MatchString(trimmed) ||
		reCredentialPlaceholder.MatchString(trimmed) ||
		reMaskOnly.MatchString(trimmed) ||
		isExactCommonPlaceholder(trimmed)
}

func isExactCommonPlaceholder(value string) bool {
	upper := strings.ToUpper(value)
	for _, placeholder := range commonPlaceholders {
		if upper == placeholder {
			return true
		}
	}
	return false
}

func looksLikeURLMatch(value string) bool {
	return strings.Contains(value, "://") || reHostPortPrefix.MatchString(value)
}

func isLikelyPlaceholder(value string) bool {
	upper := strings.ToUpper(value)
	for _, placeholder := range commonPlaceholders {
		if strings.Contains(upper, placeholder) {
			return true
		}
	}
	return false
}

func hasJSONNoise(value string) bool { return strings.IndexByte(value, ',') >= 0 }

func isOnPathOrURLBoundary(text string, start, end int) bool {
	if start < 0 || start >= end || end > len(text) {
		return true
	}
	if strings.ContainsAny(text[start:end], pathInternalChars) {
		return true
	}
	if start > 0 && strings.IndexByte(pathBoundaryChars, text[start-1]) >= 0 {
		return true
	}
	if end < len(text) && strings.IndexByte(pathBoundaryChars, text[end]) >= 0 {
		return true
	}
	lookbackStart := start - 8
	if lookbackStart < 0 {
		lookbackStart = 0
	}
	lookback := text[lookbackStart:start]
	for _, prefix := range urlPrefixes {
		if strings.Contains(lookback, prefix) {
			return true
		}
	}
	return false
}

func hasSecretContext(text string, start, end int) bool {
	if start < 0 || start >= end || end > len(text) {
		return false
	}
	lookbackStart := contextStart(text, start)
	return reSecretContext.MatchString(text[lookbackStart:contextProbeEnd(text, start, end)])
}

// hasStrongSecretContext requires the final semantic keyword to touch the
// candidate through assignment characters. In the original dependency, a
// keyword overlapping the entropy candidate (for example
// "api keyABCDEFGHIJKLMNOPQRSTUVWXYZ") made last[1] greater than candidateStart
// and caused a reversed slice. Overlap is now handled before slicing, and all
// externally-derived indexes are validated.
func hasStrongSecretContext(text string, start, end int) bool {
	if start < 0 || start >= end || end > len(text) {
		return false
	}
	lookbackStart := contextStart(text, start)
	if reAuthHeaderPrefix.MatchString(text[lookbackStart:start]) {
		return true
	}
	region := text[lookbackStart:contextProbeEnd(text, start, end)]
	lastStart, lastEnd, found := lastMatchIndex(reSecretContext, region)
	if !found {
		return false
	}
	candidateStart := start - lookbackStart
	if candidateStart < 0 || candidateStart > len(region) || lastStart < 0 || lastEnd < lastStart || lastEnd > len(region) {
		return false
	}
	// The keyword starts in, or extends into, the candidate. This is the issue
	// #3 overlap case and is a strong context without any intervening bytes.
	if lastStart >= candidateStart || lastEnd > candidateStart {
		return true
	}
	between := region[lastEnd:candidateStart]
	for i := 0; i < len(between); i++ {
		if strings.IndexByte(assignmentChars, between[i]) < 0 {
			return false
		}
	}
	return true
}

func contextProbeEnd(text string, start, end int) int {
	probeEnd := start + contextOverlapLookahead
	if probeEnd < start || probeEnd > end {
		probeEnd = end
	}
	if probeEnd > len(text) {
		probeEnd = len(text)
	}
	return probeEnd
}

func contextStart(text string, start int) int {
	lookbackStart := start - contextLookback
	if lookbackStart < 0 {
		lookbackStart = 0
	}
	// Keep regex input valid UTF-8 whenever text itself is valid. The budget and
	// public offsets remain byte-based.
	for lookbackStart < start && lookbackStart < len(text) && !utf8.RuneStart(text[lookbackStart]) {
		lookbackStart++
	}
	return lookbackStart
}

func lastMatchIndex(re *regexp.Regexp, text string) (start, end int, found bool) {
	offset := 0
	for offset <= len(text) {
		location := re.FindStringIndex(text[offset:])
		if location == nil {
			break
		}
		start, end, found = offset+location[0], offset+location[1], true
		advance := location[1]
		if advance == 0 {
			if offset == len(text) {
				break
			}
			_, width := utf8.DecodeRuneInString(text[offset:])
			if width <= 0 {
				width = 1
			}
			advance = width
		}
		offset += advance
	}
	return start, end, found
}

func isTemplateVar(value string) bool { return reTemplateVar.MatchString(value) }

func isHexHash(value string) bool {
	length := len(value)
	return (length == 32 || length == 40 || length == 64) && reHexOnly.MatchString(value)
}

func isUUID(value string) bool { return reUUID.MatchString(value) }

func isBusinessIDAssignment(value string) bool {
	equals := strings.IndexByte(value, '=')
	if equals <= 0 {
		return false
	}
	name := strings.ToLower(value[:equals])
	for _, credentialWord := range []string{"key", "secret", "token", "auth", "password", "credential"} {
		if strings.Contains(name, credentialWord) {
			return false
		}
	}
	for _, suffix := range benignIDSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func ruleApplies(rule *secretRule, lowerText string) bool {
	if len(rule.keywords) == 0 {
		return true
	}
	for _, keyword := range rule.keywords {
		if strings.Contains(lowerText, keyword) {
			return true
		}
	}
	return false
}

func shannonEntropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}
	var frequency [256]float64
	for i := 0; i < len(value); i++ {
		frequency[value[i]]++
	}
	length := float64(len(value))
	entropy := 0.0
	for _, count := range frequency {
		if count == 0 {
			continue
		}
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

type allowlistCandidate struct {
	secret string
	match  string
	line   string
}

func anyAllowlisted(allowlists []compiledAllowlist, candidate allowlistCandidate) bool {
	for i := range allowlists {
		if allowlists[i].matches(candidate) {
			return true
		}
	}
	return false
}

func (allowlist *compiledAllowlist) matches(candidate allowlistCandidate) bool {
	if allowlist == nil {
		return false
	}
	target := candidate.secret
	switch allowlist.target {
	case allowlistMatch:
		target = candidate.match
	case allowlistLine:
		target = candidate.line
	}
	regexMatched := false
	for _, re := range allowlist.regexes {
		// Gitleaks treats an empty-only regex match as non-matching.
		if re.FindString(target) != "" {
			regexMatched = true
			break
		}
	}
	stopwordMatched := false
	lowerSecret := strings.ToLower(candidate.secret)
	for _, stopword := range allowlist.stopwords {
		if strings.Contains(lowerSecret, stopword) {
			stopwordMatched = true
			break
		}
	}
	if allowlist.condition == allowlistAND {
		return (len(allowlist.regexes) == 0 || regexMatched) &&
			(len(allowlist.stopwords) == 0 || stopwordMatched)
	}
	return regexMatched || stopwordMatched
}

func lineContaining(text string, start, end int) string {
	if start < 0 || start > end || end > len(text) {
		return ""
	}
	lineStart := strings.LastIndexByte(text[:start], '\n') + 1
	lineEnd := len(text)
	if relative := strings.IndexByte(text[end:], '\n'); relative >= 0 {
		lineEnd = end + relative
	}
	return text[lineStart:lineEnd]
}

func forEachEntropyToken(ctx context.Context, text string, visit func(start, end int) error) error {
	start := -1
	for i := 0; i <= len(text); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		allowed := i < len(text) && isEntropyTokenByte(text[i])
		if allowed {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 20 {
			if err := visit(start, i); err != nil {
				return err
			}
		}
		start = -1
	}
	return nil
}

func hasASCIIUpper(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 'A' && value[i] <= 'Z' {
			return true
		}
	}
	return false
}

// entropyTokenByte is one comparison per input byte. The set is ASCII letters,
// digits, and the base64/url token characters used by forEachEntropyToken.
var entropyTokenByte = func() [256]bool {
	var table [256]bool
	for value := byte('a'); value <= 'z'; value++ {
		table[value] = true
	}
	for value := byte('A'); value <= 'Z'; value++ {
		table[value] = true
	}
	for value := byte('0'); value <= '9'; value++ {
		table[value] = true
	}
	for _, value := range []byte{'+', '/', '=', '_', '-'} {
		table[value] = true
	}
	return table
}()

func isEntropyTokenByte(value byte) bool {
	return entropyTokenByte[value]
}

func forEachMatchIndex(ctx context.Context, re *regexp.Regexp, text string, visit func(start, end int) error) error {
	return forEachSubmatchIndex(ctx, re, text, func(indices []int) error {
		if len(indices) < 2 {
			return nil
		}
		return visit(indices[0], indices[1])
	})
}

// forEachSubmatchIndex iterates without materializing every match. This keeps
// memory bounded by one match even on an input containing hundreds of
// thousands of candidates.
func forEachSubmatchIndex(ctx context.Context, re *regexp.Regexp, text string, visit func([]int) error) error {
	offset := 0
	for offset <= len(text) {
		if err := ctx.Err(); err != nil {
			return err
		}
		indices := re.FindStringSubmatchIndex(text[offset:])
		if indices == nil {
			return nil
		}
		for i, index := range indices {
			if index >= 0 {
				indices[i] = offset + index
			}
		}
		if err := visit(indices); err != nil {
			return err
		}
		matchEnd := indices[1]
		if matchEnd > offset {
			offset = matchEnd
			continue
		}
		if offset == len(text) {
			return nil
		}
		_, width := utf8.DecodeRuneInString(text[offset:])
		if width <= 0 {
			width = 1
		}
		offset += width
	}
	return nil
}
