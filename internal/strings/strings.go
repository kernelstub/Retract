package strings

import (
	"regexp"
	"unicode/utf8"

	"retract/pkg/api"
)

var (
	urlRe        = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
	ipv4Re       = regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b`)
	ipv6Re       = regexp.MustCompile(`(?i)\b([0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b`)
	domainRe     = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.)+[a-z]{2,}\b`)
	pathRe       = regexp.MustCompile(`(?i)([a-z]:\\|\\\\[a-z0-9_.-]+\\[a-z0-9_.-]+|/(usr|bin|etc|tmp|var|home|opt|dev|proc)/)[^\x00\r\n\t"']+`)
	regRe        = regexp.MustCompile(`(?i)\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\x00\r\n]+`)
	uaRe         = regexp.MustCompile(`(?i)mozilla/|user-agent|curl/|wget/`)
	mutexRe      = regexp.MustCompile(`(?i)\b((global|local)\\[a-z0-9_.-]{6,}|\{[0-9a-f-]{32,}\}|[a-z0-9_-]{18,})\b`)
	commandRe    = regexp.MustCompile(`(?i)\b(cmd\.exe|powershell|/bin/sh|wscript|rundll32|regsvr32)\b`)
	cryptoRe     = regexp.MustCompile(`(?i)\b(aes|rsa|sha256|sha1|md5|crypt|bcrypt|rc4|base64)\b`)
	suspiciousRe = regexp.MustCompile(`(?i)\b(inject|keylog|download|shellcode|payload|debugger|sandbox|autorun|schtasks)\b`)
	apiRe        = regexp.MustCompile(`\b(Create|Open|Read|Write|Delete|Virtual|LoadLibrary|GetProc|Reg|Internet|Crypt|Nt|Zw|IsDebugger|CheckRemote)[A-Za-z0-9_]*(A|W)?\b`)
)

func Extract(data []byte, min int) []api.StringHit {
	if min <= 0 {
		min = 4
	}
	hits := append(extractASCII(data, min), extractUTF16LE(data, min)...)
	for i := range hits {
		hits[i].Tags = Categorize(hits[i].Value)
	}
	return hits
}

func extractASCII(data []byte, min int) []api.StringHit {
	var hits []api.StringHit
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			s := string(data[start:i])
			enc := "ascii"
			if utf8.ValidString(s) {
				enc = "utf-8"
			}
			hits = append(hits, api.StringHit{Value: s, Offset: start, Encoding: enc})
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= min {
		hits = append(hits, api.StringHit{Value: string(data[start:]), Offset: start, Encoding: "ascii"})
	}
	return hits
}

func extractUTF16LE(data []byte, min int) []api.StringHit {
	var hits []api.StringHit
	hits = append(hits, extractUTF16LEAligned(data, min, 0)...)
	hits = append(hits, extractUTF16LEAligned(data, min, 1)...)
	return hits
}

func extractUTF16LEAligned(data []byte, min, align int) []api.StringHit {
	var hits []api.StringHit
	start := -1
	var run []rune
	for i := align; i+1 < len(data); i += 2 {
		lo, hi := data[i], data[i+1]
		if hi == 0 && lo >= 0x20 && lo <= 0x7e {
			if start < 0 {
				start = i
			}
			run = append(run, rune(lo))
			continue
		}
		if start >= 0 && len(run) >= min {
			hits = append(hits, api.StringHit{Value: string(run), Offset: start, Encoding: "utf-16le"})
		}
		start = -1
		run = nil
	}
	if start >= 0 && len(run) >= min {
		hits = append(hits, api.StringHit{Value: string(run), Offset: start, Encoding: "utf-16le"})
	}
	return hits
}

func Categorize(s string) []string {
	tags := []string{}
	add := func(tag string) { tags = append(tags, tag) }
	if urlRe.MatchString(s) {
		add("url")
	}
	if domainRe.MatchString(s) {
		add("domain")
	}
	if ipv4Re.MatchString(s) || ipv6Re.MatchString(s) {
		add("ip")
	}
	if pathRe.MatchString(s) {
		add("path")
	}
	if regRe.MatchString(s) {
		add("registry")
	}
	if uaRe.MatchString(s) {
		add("user-agent")
	}
	if mutexRe.MatchString(s) {
		add("mutex-like")
	}
	if commandRe.MatchString(s) {
		add("command")
	}
	if cryptoRe.MatchString(s) {
		add("crypto")
	}
	if suspiciousRe.MatchString(s) {
		add("suspicious")
	}
	if apiRe.MatchString(s) {
		add("windows-api-like")
	}
	return tags
}
