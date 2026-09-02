package md

import "testing"

func TestMdToHTML(t *testing.T) {
	cases := []struct{ in, want string }{
		{"**bold** and *it*", "<b>bold</b> and <i>it</i>"},
		{"a < b & c > d", "a &lt; b &amp; c &gt; d"},
		{"`x < y`", "<code>x &lt; y</code>"},
		{"# Head", "<b>Head</b>"},
		{"- one\n- two", "• one\n• two"},
		{"[go](https://go.dev)", `<a href="https://go.dev">go</a>`},
		{"~~no~~", "<s>no</s>"},
		{"```go\nif a < b {}\n```", "<pre><code class=\"language-go\">if a &lt; b {}</code></pre>"},
		{"**a** `code with *stars*`", "<b>a</b> <code>code with *stars*</code>"},
	}
	for _, c := range cases {
		if got := ToHTML(c.in); got != c.want {
			t.Errorf("ToHTML(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestStripTags(t *testing.T) {
	if got := StripTags("<b>a &lt; b</b>"); got != "a < b" {
		t.Errorf("got %q", got)
	}
}
