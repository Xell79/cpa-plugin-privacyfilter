package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

//go:embed ml_model.json
var mlModelJSON []byte

// mlRuleID identifies ML second-opinion findings in logs and rendered output.
const mlRuleID = "ml.second-opinion"

// mlModel is the exported sensitive-text student: standardized logistic
// regression over 17 structural features. See train_v2.py (distillation
// from SystemOne teacher labels on historical + synthetic prompts).
type mlModel struct {
	Keys      []string  `json:"keys"`
	Mean      []float64 `json:"mean"`
	Scale     []float64 `json:"scale"`
	Coef      []float64 `json:"coef"`
	Intercept float64   `json:"intercept"`
	Threshold float64   `json:"threshold"`
}

var mlState = struct {
	sync.Once
	model *mlModel
	err   error
}{}

func loadMLModel() (*mlModel, error) {
	mlState.Once.Do(func() {
		var m mlModel
		if err := json.Unmarshal(mlModelJSON, &m); err != nil {
			mlState.err = fmt.Errorf("privacyfilter: invalid embedded ml model: %w", err)
			return
		}
		if len(m.Keys) == 0 || len(m.Keys) != len(m.Mean) || len(m.Keys) != len(m.Scale) || len(m.Keys) != len(m.Coef) {
			mlState.err = fmt.Errorf("privacyfilter: embedded ml model has inconsistent dimensions")
			return
		}
		for _, s := range m.Scale {
			if s == 0 {
				mlState.err = fmt.Errorf("privacyfilter: embedded ml model has zero scale")
				return
			}
		}
		mlState.model = &m
	})
	return mlState.model, mlState.err
}

var (
	mlReEmail     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	mlRePhone     = regexp.MustCompile(`1[3-9][0-9]{9}`)
	mlReIDCN      = regexp.MustCompile(`[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx]`)
	mlReIPv4      = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	mlReAKIA      = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	mlReGH        = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)
	mlReSlack     = regexp.MustCompile(`xox[bap]-[A-Za-z0-9\-]{10,}`)
	mlReStripe    = regexp.MustCompile(`sk_live_[A-Za-z0-9]{8,}`)
	mlReCredField = regexp.MustCompile(`(?i)(api[_-]?key|secret|password|passwd|pwd|token|bearer)["']?\s*[:=]\s*["']?[A-Za-z0-9\-_!@#$%^&*.]{6,}`)
	mlReToken     = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{8,}`)
	mlReMaskOnly  = regexp.MustCompile(`10\.0\.0\.0/8|/8\s*待定`)
	mlReNameOnly  = regexp.MustCompile(`(api_key_name|token_id)\s*=`)
)

// mlDigitBounded mirrors the training feature's digit-boundary rule: a match
// only counts when no ASCII digit touches either side.
func mlDigitBounded(s string, start, end int) bool {
	if start > 0 {
		if c := s[start-1]; c >= '0' && c <= '9' {
			return false
		}
	}
	if end < len(s) {
		if c := s[end]; c >= '0' && c <= '9' {
			return false
		}
	}
	return true
}

func mlHasBounded(re *regexp.Regexp, s string) bool {
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if mlDigitBounded(s, loc[0], loc[1]) {
			return true
		}
	}
	return false
}

func mlEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	ent := 0.0
	for _, v := range counts {
		p := float64(v) / float64(n)
		ent -= p * math.Log2(p)
	}
	return ent
}

func mlIsUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func mlIsLower(r rune) bool { return r >= 'a' && r <= 'z' }
func mlIsDigit(r rune) bool { return r >= '0' && r <= '9' }

// mlFeatures extracts the 17 structural features in ml_model.json key order.
// Order and semantics must match train_v2.py exactly.
func mlFeatures(text string) []float64 {
	f := make([]float64, 17)
	if mlReEmail.MatchString(text) {
		f[0] = 1
	}
	if mlHasBounded(mlRePhone, text) {
		f[1] = 1
	}
	if mlHasBounded(mlReIDCN, text) {
		f[2] = 1
	}
	if mlHasBounded(mlReIPv4, text) {
		f[3] = 1
	}
	if mlReAKIA.MatchString(text) {
		f[4] = 1
	}
	if mlReGH.MatchString(text) {
		f[5] = 1
	}
	if strings.Contains(text, "PRIVATE KEY") {
		f[6] = 1
	}
	if mlReSlack.MatchString(text) {
		f[7] = 1
	}
	if mlReStripe.MatchString(text) {
		f[8] = 1
	}
	cred := 0.0
	if mlReCredField.MatchString(text) {
		cred = 1
	}
	f[9] = cred
	nMixed := 0
	maxEnt := 0.0
	nHighEnt := 0
	maxRun := 0
	for _, loc := range mlReToken.FindAllStringIndex(text, -1) {
		w := text[loc[0]:loc[1]]
		if r := utf8.RuneCountInString(w); r > maxRun {
			maxRun = r
		}
		up, low, dig := 0, 0, 0
		for _, r := range w {
			switch {
			case mlIsUpper(r):
				up++
			case mlIsLower(r):
				low++
			case mlIsDigit(r):
				dig++
			}
		}
		if utf8.RuneCountInString(w) >= 12 && up >= 2 && dig >= 2 && low >= 2 {
			nMixed++
		}
		ent := mlEntropy(w)
		if ent > maxEnt {
			maxEnt = ent
		}
		if utf8.RuneCountInString(w) >= 12 && ent > 4.2 {
			nHighEnt++
		}
	}
	f[10] = float64(nMixed)
	f[11] = maxEnt
	f[12] = float64(nHighEnt)
	f[13] = float64(maxRun)
	lowered := strings.ToLower(text)
	allow := 0.0
	if strings.Contains(lowered, "example") || strings.Contains(lowered, "placeholder") ||
		strings.Contains(lowered, "xxx") || strings.Contains(lowered, "test-please-replace") ||
		strings.Contains(text, "自行申请") || strings.Contains(text, "通讯录") ||
		strings.Contains(lowered, "do not use") {
		allow = 1
	}
	f[14] = allow
	if mlReMaskOnly.MatchString(text) {
		f[15] = 1
	}
	if mlReNameOnly.MatchString(text) && cred == 0 {
		f[16] = 1
	}
	return f
}

// mlScore returns the sensitive-text probability in [0,1]. An error means
// the embedded model failed to load; callers must fail open (skip ML) since
// the deterministic engine already ran.
func mlScore(text string) (float64, error) {
	model, err := loadMLModel()
	if err != nil {
		return 0, err
	}
	features := mlFeatures(text)
	z := model.Intercept
	for i, v := range features {
		z += ((v - model.Mean[i]) / model.Scale[i]) * model.Coef[i]
	}
	return 1 / (1 + math.Exp(-z)), nil
}
