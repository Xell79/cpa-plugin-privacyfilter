package privacyengine

// PII detection in this file is derived from packyme/privacy-filter/filter/pii.go
// at commit 64b8de3c2060. See LICENSE in this directory.

import (
	"context"
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

func detectPII(ctx context.Context, text string, collector *spanCollector) error {
	if err := forEachMatchIndex(ctx, reEmail, text, func(start, end int) error {
		if end < len(text) && text[end] == ':' && end+1 < len(text) && text[end+1] != ' ' && text[end+1] != '\t' {
			return nil
		}
		if isInSSHCommandContext(text, start) {
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
		if !ipBounded(text, start, end) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindIP, ruleID: rulePIIIPv4})
	}); err != nil {
		return err
	}
	return forEachMatchIndex(ctx, reBankCard, text, func(start, end int) error {
		if !digitBounded(text, start, end) || !luhnValid(text[start:end]) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindBankCard, ruleID: rulePIIBankCard})
	})
}
