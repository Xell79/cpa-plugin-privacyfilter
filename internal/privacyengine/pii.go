package privacyengine

// PII detection in this file is derived from packyme/privacy-filter/filter/pii.go
// at commit 64b8de3c2060. See LICENSE in this directory.

import (
	"context"
	"net"
	"regexp"
	"strings"
)

var (
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhoneCN  = regexp.MustCompile(`(?:\+?86[-\s]?)?1[3-9][0-9]{9}`)
	reIDCard   = regexp.MustCompile(`[1-9][0-9]{16}[0-9Xx]`)
	reBankCard = regexp.MustCompile(`[0-9]{13,19}`)
	reIPv4     = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)
)

var sshCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

func isInSSHCommandContext(text string, emailStart int) bool {
	if emailStart < 0 || emailStart > len(text) {
		return false
	}
	lineStart := strings.LastIndexByte(text[:emailStart], '\n') + 1
	line := text[lineStart:emailStart]
	for _, command := range sshCommands {
		if strings.Contains(line, command) {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func digitBounded(text string, start, end int) bool {
	if start < 0 || start > end || end > len(text) {
		return false
	}
	if start > 0 && isDigit(text[start-1]) {
		return false
	}
	if end < len(text) && isDigit(text[end]) {
		return false
	}
	return true
}

func ipBounded(text string, start, end int) bool {
	if start < 0 || start > end || end > len(text) {
		return false
	}
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

func isDocumentationEmail(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at+1 >= len(email) {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	switch domain {
	case "example.com", "example.org", "example.net", "example.edu":
		return true
	default:
		return strings.HasSuffix(domain, ".invalid") || strings.HasSuffix(domain, ".localhost")
	}
}

func isNonPublicIPv4(value string) bool {
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// RFC 5737 documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
	return (ip[0] == 192 && ip[1] == 0 && ip[2] == 2) ||
		(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
		(ip[0] == 203 && ip[1] == 0 && ip[2] == 113)
}

func isExampleBankCard(number string) bool {
	if len(number) == 0 {
		return false
	}
	same := true
	for i := 1; i < len(number); i++ {
		if number[i] != number[0] {
			same = false
			break
		}
	}
	if same {
		return true
	}
	switch number {
	case "4111111111111111", "4242424242424242", "4000000000000002", "5555555555554444", "378282246310005":
		return true
	default:
		return false
	}
}

func luhnValid(number string) bool {
	if number == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		if !isDigit(number[i]) {
			return false
		}
		digit := int(number[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

// hasPaymentCardPrefix accepts Visa, Mastercard, and American Express
// issuer ranges. A Luhn-valid digit run outside those ranges is not a card.
func hasPaymentCardPrefix(number string) bool {
	if len(number) < 13 {
		return false
	}
	switch number[0] {
	case '4':
		return len(number) == 13 || len(number) == 16 || len(number) == 19
	case '5':
		return len(number) == 16 && number[1] >= '1' && number[1] <= '5'
	case '3':
		return len(number) == 15 && (number[1] == '4' || number[1] == '7')
	default:
		return false
	}
}

// isEmailBoundary reports whether an address is a user identity rather than
// part of a URL or a user:password token. A colon or slash immediately before
// the local part is that boundary.
func isEmailBoundary(text string, start int) bool {
	return start == 0 || (text[start-1] != ':' && text[start-1] != '/')
}

func detectPII(ctx context.Context, text string, collector *spanCollector) error {
	if err := forEachMatchIndex(ctx, reEmail, text, func(start, end int) error {
		if end < len(text) && text[end] == ':' && end+1 < len(text) && text[end+1] != ' ' && text[end+1] != '\t' {
			return nil
		}
		if !isEmailBoundary(text, start) || isInSSHCommandContext(text, start) || isDocumentationEmail(text[start:end]) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindEmail, ruleID: rulePIIEmail})
	}); err != nil {
		return err
	}
	hasDigit := false
	for i := 0; i < len(text); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if isDigit(text[i]) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return nil
	}

	if err := forEachMatchIndex(ctx, rePhoneCN, text, func(start, end int) error {
		if !digitBounded(text, start, end) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindPhone, ruleID: rulePIIPhoneCN})
	}); err != nil {
		return err
	}
	if err := forEachMatchIndex(ctx, reIDCard, text, func(start, end int) error {
		if !digitBounded(text, start, end) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindIDCard, ruleID: rulePIIIDCardCN})
	}); err != nil {
		return err
	}
	if err := forEachMatchIndex(ctx, reIPv4, text, func(start, end int) error {
		if !ipBounded(text, start, end) || isNonPublicIPv4(text[start:end]) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindIP, ruleID: rulePIIIPv4})
	}); err != nil {
		return err
	}
	return forEachMatchIndex(ctx, reBankCard, text, func(start, end int) error {
		number := text[start:end]
		if !digitBounded(text, start, end) || !hasPaymentCardPrefix(number) || !luhnValid(number) || isExampleBankCard(number) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindBankCard, ruleID: rulePIIBankCard})
	})
}
