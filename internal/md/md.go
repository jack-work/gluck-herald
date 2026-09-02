package md

import (
	"regexp"
	"strings"
)

// Markdown -> Telegram HTML.
//
// HTML is the pragmatic parse_mode: only & < > need escaping and Telegram
// tolerates unknown tags, where MarkdownV2 demands 18+ escapes and drops the
// whole message on a single miss. Supported tags: b i u s code pre a
// blockquote tg-spoiler.
//
// Strategy (the standard one): pull fenced/inline code out into placeholders
// first so no inline rule can touch their contents, escape everything, apply
// the inline rules, then put the code back.

var (
	reFence  = regexp.MustCompile("(?s)```[ \\t]*([A-Za-z0-9_+-]*)[ \\t]*\r?\n(.*?)```")
	reTick   = regexp.MustCompile("`([^`\n]+)`")
	reLink   = regexp.MustCompile(`\[([^\]\n]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	reBold   = regexp.MustCompile(`\*\*([^*\n]+)\*\*|__([^_\n]+)__`)
	reItalic = regexp.MustCompile(`(^|[\s(])[*_]([^*_\n]+)[*_]($|[\s).,!?;:])`)
	reStrike = regexp.MustCompile(`~~([^~\n]+)~~`)
	reHead   = regexp.MustCompile(`(?m)^#{1,6}[ \t]+(.+)$`)
	reBullet = regexp.MustCompile(`(?m)^([ \t]*)[-*+][ \t]+`)
	// RE2 has no backreferences, so each rule spells out its own bullet.
	reHR = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]*){3,}$|^[ \t]*(?:\*[ \t]*){3,}$|^[ \t]*(?:_[ \t]*){3,}$`)
	rePH = regexp.MustCompile("\x00(\\d+)\x00")
)

func escapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// ToHTML renders a useful subset of markdown as Telegram HTML.
func ToHTML(md string) string {
	var stash []string
	keep := func(html string) string {
		stash = append(stash, html)
		return "\x00" + itoa(len(stash)-1) + "\x00"
	}

	s := strings.ReplaceAll(md, "\r\n", "\n")

	s = reFence.ReplaceAllStringFunc(s, func(m string) string {
		g := reFence.FindStringSubmatch(m)
		lang, body := g[1], strings.TrimRight(g[2], "\n")
		open := "<pre><code>"
		if lang != "" {
			open = `<pre><code class="language-` + escapeHTML(lang) + `">`
		}
		return keep(open + escapeHTML(body) + "</code></pre>")
	})
	s = reTick.ReplaceAllStringFunc(s, func(m string) string {
		return keep("<code>" + escapeHTML(reTick.FindStringSubmatch(m)[1]) + "</code>")
	})

	s = escapeHTML(s)

	s = reHR.ReplaceAllString(s, "──────────")
	s = reHead.ReplaceAllString(s, "<b>$1</b>")
	s = reLink.ReplaceAllString(s, `<a href="$2">$1</a>`)
	s = reBold.ReplaceAllStringFunc(s, func(m string) string {
		g := reBold.FindStringSubmatch(m)
		inner := g[1]
		if inner == "" {
			inner = g[2]
		}
		return "<b>" + inner + "</b>"
	})
	s = reItalic.ReplaceAllString(s, "$1<i>$2</i>$3")
	s = reStrike.ReplaceAllString(s, "<s>$1</s>")
	s = reBullet.ReplaceAllString(s, "$1• ")

	s = rePH.ReplaceAllStringFunc(s, func(m string) string {
		i := atoi(rePH.FindStringSubmatch(m)[1])
		if i < 0 || i >= len(stash) {
			return ""
		}
		return stash[i]
	})
	return strings.TrimSpace(s)
}

// StripTags renders HTML back to plain text — the fallback when Telegram
// rejects our markup, so a message is never lost to a parse error.
func StripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`)
	return r.Replace(b.String())
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}
