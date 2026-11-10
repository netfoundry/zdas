package zdas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// PageBranding changes how the pages ZDAS shows a browser look: the consent
// page /authorize shows, and the error pages of /authorize, /callback and
// Handler.CompleteProvision. Every field is optional, and an empty one keeps
// ZDAS's default. The consent page's warning, its place before the buttons
// and the form that posts back can't be changed. A rate-limit refusal stays
// plain text, so that a flood of requests never asks for branding.
//
// Text is shown as plain text, without control and format characters, and
// cut to a label's length. A logo or color that isn't valid is left out and
// logged, once for each value.
type PageBranding struct {
	// Title is the page's title and heading. The default is "Sign in to
	// OpenZiti".
	Title string
	// Intro is the line under the consent page's heading. The default is
	// "An app asked to sign you in to an OpenZiti network."
	Intro string
	// ProviderLabels maps a provider's name to the label on its button,
	// "Continue with <label>". A provider without one shows its name.
	ProviderLabels map[string]string
	// Logo is an image shown above the heading: a data: URI of a PNG, JPEG,
	// GIF, WebP or SVG image, at most 16 KiB as written (base64 included),
	// or the path of a static file on ZDAS's own origin, without a query or
	// fragment, such as "/static/logo.svg". A browser fetches a path with
	// the user's cookies, so it must be a plain file. LogoDark, if set,
	// replaces Logo when the browser prefers a dark color scheme; set on its
	// own, it shows only then.
	Logo, LogoDark string
	// PrimaryColor fills the consent page's buttons, as #rgb or #rrggbb,
	// with white text, so it must be dark enough for white text to read on
	// it. PrimaryHoverColor fills them on hover, defaults to PrimaryColor,
	// and is ignored without it.
	PrimaryColor, PrimaryHoverColor string
}

// Defaults and limits for PageBranding.
const (
	defaultPageTitle = "Sign in to OpenZiti"
	defaultPageIntro = "An app asked to sign you in to an OpenZiti network."

	maxPageTitleRunes     = 120
	maxPageIntroRunes     = 300
	maxProviderLabelRunes = 64
	maxLogoBytes          = 16 << 10
)

// pageStyle is the branding a page is rendered with, checked and with
// defaults filled in.
type pageStyle struct {
	Title, Intro          string
	Logo, LogoDark        template.URL
	Primary, PrimaryHover template.CSS
	labels                map[string]string
}

// label returns the button label for provider.
func (p pageStyle) label(provider string) string {
	if l := displayText(p.labels[provider], maxProviderLabelRunes); l != "" {
		return l
	}
	return provider
}

// pageStyle returns the branding for a page answering r.
func (h *endpoints) pageStyle(r *http.Request) pageStyle {
	b := h.callBranding(r)
	p := pageStyle{
		Title:  displayText(b.Title, maxPageTitleRunes),
		Intro:  displayText(b.Intro, maxPageIntroRunes),
		labels: b.ProviderLabels,
	}
	if p.Title == "" {
		p.Title = defaultPageTitle
	}
	if p.Intro == "" {
		p.Intro = defaultPageIntro
	}
	var problem string
	if p.Logo, problem = logoURL(b.Logo); problem != "" {
		h.warnBranding(r, "Logo", b.Logo, problem)
	}
	if p.LogoDark, problem = logoURL(b.LogoDark); problem != "" {
		h.warnBranding(r, "LogoDark", b.LogoDark, problem)
	}
	if p.Primary, problem = cssColor(b.PrimaryColor); problem != "" {
		h.warnBranding(r, "PrimaryColor", b.PrimaryColor, problem)
	}
	if p.PrimaryHover, problem = cssColor(b.PrimaryHoverColor); problem != "" {
		h.warnBranding(r, "PrimaryHoverColor", b.PrimaryHoverColor, problem)
	}
	// The page uses PrimaryHover only with Primary.
	switch {
	case p.Primary == "" && p.PrimaryHover != "":
		h.warnBranding(r, "PrimaryHoverColor", b.PrimaryHoverColor, "ignored without a valid PrimaryColor")
	case p.PrimaryHover == "":
		p.PrimaryHover = p.Primary
	}
	return p
}

// callBranding returns the embedder's branding for r. If its function
// panics, it returns the zero PageBranding, so the page keeps ZDAS's own
// look and a sign-in whose session a handler has already consumed still
// gets its page.
func (h *endpoints) callBranding(r *http.Request) (b PageBranding) {
	if h.branding == nil {
		return b
	}
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			msg := fmt.Sprint(v)
			if h.brandingWarned.first("panic\x00" + msg) {
				h.logger.Error("page branding function panicked; using ZDAS's own look", "panic", truncForLog(msg), "host", truncForLog(r.Host))
			}
		}
	}()
	return h.branding(r)
}

// warnBranding logs that the value of the PageBranding field named field is
// not used, and why, the first time it sees that value. Pages are rendered
// for anyone, so a bad value logs once rather than on every request.
func (h *endpoints) warnBranding(r *http.Request, field, value, problem string) {
	sum := sha256.Sum256([]byte(value))
	if h.brandingWarned.first(field + "\x00" + hex.EncodeToString(sum[:8])) {
		h.logger.Warn("ignoring page branding: "+problem, "field", field, "host", truncForLog(r.Host))
	}
}

// maxBrandingWarnings caps how many invalid branding values are remembered
// as logged. Past it, new ones aren't logged, so changing values can't grow
// memory.
const maxBrandingWarnings = 256

// onceSet reports each key the first time it sees it, up to
// maxBrandingWarnings keys. The zero value is ready to use.
type onceSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// first reports whether key is new, and records it if there is room.
func (o *onceSet) first(key string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.seen[key]; ok || len(o.seen) >= maxBrandingWarnings {
		return false
	}
	if o.seen == nil {
		o.seen = make(map[string]struct{})
	}
	o.seen[key] = struct{}{}
	return true
}

// logoDataURIRe matches the start of a data: URI of an image type a page may
// show.
var logoDataURIRe = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp|svg\+xml)[;,]`)

// logoURL returns logo for a page's img src, or "" and the reason when logo
// is neither a data: URI of an image within maxLogoBytes nor the path of a
// file on ZDAS's origin. An empty logo returns "" and no reason.
func logoURL(logo string) (template.URL, string) {
	switch {
	case logo == "":
		return "", ""
	case strings.HasPrefix(logo, "data:"):
		if len(logo) > maxLogoBytes || !logoDataURIRe.MatchString(logo) {
			return "", "logo is not a data: URI of a PNG, JPEG, GIF, WebP or SVG image of at most 16 KiB"
		}
	case !sameOriginPath(logo):
		return "", "logo is neither a data: URI nor the path of a file on ZDAS's origin"
	}
	return template.URL(logo), ""
}

// sameOriginPath reports whether s is the path of a file a browser fetches
// from the page's own origin: it starts with one slash, and has no
// backslash, which browsers read as a slash, no query or fragment, and no
// whitespace or control characters.
func sameOriginPath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || len(s) > maxRedirectURILength {
		return false
	}
	for _, r := range s {
		if r == '\\' || r == '?' || r == '#' || r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// hexColorRe matches a CSS color as #rgb or #rrggbb.
var hexColorRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

// cssColor returns color for a page's style, or "" and the reason when it
// is not #rgb or #rrggbb. An empty color returns "" and no reason.
func cssColor(color string) (template.CSS, string) {
	if color == "" {
		return "", ""
	}
	if !hexColorRe.MatchString(color) {
		return "", "color is not #rgb or #rrggbb"
	}
	return template.CSS(color), ""
}

// consentPageData is what the consent page shows. Everything about the
// device comes from the request, so the page presents it as the device's
// own description, not as something ZDAS vouches for.
type consentPageData struct {
	Page      pageStyle
	Device    string           // the device's name, or its hostname on the fallback path
	Details   string           // OS and architecture, as reported
	ReturnTo  string           // the host and port the browser returns to
	Providers []providerButton // one button each
	Consent   string           // the session ID the form posts back
}

// providerButton is a consent page button: the provider it posts, and its
// label.
type providerButton struct {
	Name, Label string
}

// renderConsent shows the page the user continues from: one button per
// provider in providers, posting back to /authorize. The page cannot be
// framed, so another site cannot trick the user into clicking it.
func (h *endpoints) renderConsent(w http.ResponseWriter, r *http.Request, info *DeviceInfo, redirect *url.URL, providers []string, consentID string) {
	device := displayText(info.DeviceName, maxDisplayedDeviceRunes)
	if device == "" {
		device = displayText(info.Hostname, maxDisplayedDeviceRunes)
	}
	page := h.pageStyle(r)
	buttons := make([]providerButton, len(providers))
	for i, name := range providers {
		buttons[i] = providerButton{Name: name, Label: page.label(name)}
	}
	h.writePage(w, "consent", http.StatusOK, consentPageData{
		Page:      page,
		Device:    device,
		Details:   displayText(strings.TrimSpace(info.OS+" "+info.Arch), maxDisplayedDeviceRunes),
		ReturnTo:  redirect.Host,
		Providers: buttons,
		Consent:   consentID,
	})
}

// errorPageData is what an error page shows.
type errorPageData struct {
	Page    pageStyle
	Message string
}

// pageError answers a request a browser may have sent with msg and status:
// as an error page when the request accepts HTML, and as plain text, like
// http.Error, otherwise. Either way the response varies by Accept.
func (h *endpoints) pageError(w http.ResponseWriter, r *http.Request, msg string, status int) {
	w.Header().Add("Vary", "Accept")
	if !acceptsHTML(r) {
		http.Error(w, msg, status)
		return
	}
	h.writePage(w, "error", status, errorPageData{Page: h.pageStyle(r), Message: msg})
}

// acceptsHTML reports whether r's Accept header names text/html, as a
// browser's does for a page.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// writePage renders the page template name with data and sends it with
// status. Its headers keep it from being framed, cached, or loading anything
// but its own inline style and images.
func (h *endpoints) writePage(w http.ResponseWriter, name string, status int, data any) {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("render page", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Del("Content-Length")
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// pages holds the pages ZDAS renders. "head" opens each page, through its
// heading, from a pageStyle.
//
// The consent page's form has no action, so it posts to the page's own URL,
// wherever ZDAS is mounted. The device's description is shown as code,
// apart from ZDAS's own text, and the warning comes before the buttons.
var pages = template.Must(template.New("pages").Parse(`{{define "head"}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Title}}</title>
<style>
  :root { color-scheme: light dark; --bg: #fff; --text: #333; --muted: #666; --subtle: #f5f5f5; --border: #ddd; --hover: #e8e8e8; --hover-border: #ccc; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #121212; --text: #e5e5e5; --muted: #a3a3a3; --subtle: #262626; --border: #404040; --hover: #333; --hover-border: #525252; }
  }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; background: var(--bg); color: var(--text); }
  h1 { font-size: 1.4em; font-weight: 600; margin-bottom: 16px; }
  p { line-height: 1.4; }
  .note { font-size: 0.9em; color: var(--muted); }
  code { background: var(--subtle); padding: 1px 4px; border-radius: 4px; }
  button { display: block; width: 100%; padding: 14px 20px; margin: 8px 0; background: var(--subtle); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 1em; text-align: left; cursor: pointer; }
  button:hover { background: var(--hover); border-color: var(--hover-border); }
{{- with .Primary}}
  button { background: {{.}}; border-color: {{.}}; color: #fff; }
  button:hover { background: {{$.PrimaryHover}}; border-color: {{$.PrimaryHover}}; }
{{- end}}
  .logo { display: block; max-width: 100%; max-height: 48px; margin-bottom: 16px; }
  .logo-dark { display: none; }
  @media (prefers-color-scheme: dark) {
    .logo-light { display: none; }
    .logo-dark { display: block; }
  }
</style>
</head>
<body>
{{with .Logo}}<img class="logo{{if $.LogoDark}} logo-light{{end}}" src="{{.}}" alt="">
{{end}}{{with .LogoDark}}<img class="logo logo-dark" src="{{.}}" alt="">
{{end}}<h1>{{.Title}}</h1>
{{end}}

{{define "consent"}}{{template "head" .Page}}<p>{{.Page.Intro}}</p>
{{with .Device}}<p class="note">The app describes the device as <code>{{.}}</code>{{with $.Details}} (<code>{{.}}</code>){{end}}. Whoever started this sign-in supplied that description, and this site can't check it.</p>
{{end}}<p><strong>Continue only if you started this yourself, just now, on your own device.</strong> If someone sent you this link, or later asks for the address your browser shows, stop: they are trying to enroll a device as you.</p>
<form method="post">
<input type="hidden" name="consent" value="{{.Consent}}">
{{range .Providers}}<button type="submit" name="idp" value="{{.Name}}">Continue with {{.Label}}</button>
{{end}}</form>
<p class="note">After you sign in, your browser returns to the app at {{.ReturnTo}}. Don't copy that address or send it to anyone: it carries your sign-in.</p>
</body>
</html>
{{end}}

{{define "error"}}{{template "head" .Page}}<p>{{.Message}}</p>
</body>
</html>
{{end}}`))
