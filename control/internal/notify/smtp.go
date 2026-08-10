// Package notify handles outbound notifications — email for now, push/SMS
// later. The SMTP sender uses net/smtp with STARTTLS, authenticating via
// PLAIN with a server-configured identity.
package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig describes the outbound mail server.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string // "Deadman <noreply@example.org>"
	// InsecureSkipVerify is a dev escape hatch for local SMTP sinks like
	// mailhog. Never set in production.
	InsecureSkipVerify bool
}

// Enabled reports whether SMTP is configured enough to send.
func (c SMTPConfig) Enabled() bool { return c.Host != "" && c.Port > 0 && c.From != "" }

// Sender sends messages.
type Sender struct {
	cfg SMTPConfig
}

func NewSender(cfg SMTPConfig) *Sender { return &Sender{cfg: cfg} }

// Send delivers a single message. Returns nil on success. One connection per
// call; fine for M3 release-worker scale (handful of mails per trigger).
// The whole SMTP session runs under ctx and an absolute I/O deadline, so a
// hung or silent server cannot block the caller indefinitely.
func (s *Sender) Send(ctx context.Context, to []string, subject, textBody string) error {
	if !s.cfg.Enabled() {
		return errors.New("smtp: not configured")
	}
	if len(to) == 0 {
		return errors.New("smtp: no recipients")
	}
	fromAddr, err := mail.ParseAddress(s.cfg.From)
	if err != nil {
		return fmt.Errorf("smtp: invalid From: %w", err)
	}
	for _, t := range to {
		if _, err := mail.ParseAddress(t); err != nil {
			return fmt.Errorf("smtp: invalid recipient %q: %w", t, err)
		}
	}

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))

	// Dial, EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA.
	// net/smtp doesn't pick STARTTLS automatically when starting from 587;
	// we drive it explicitly so we can verify TLS config.
	dialer := net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	// Absolute deadline for the whole session (greeting through QUIT) so a
	// hung server cannot block forever; honor an earlier ctx deadline.
	deadline := time.Now().Add(2 * time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: set deadline: %w", err)
	}
	// If ctx is canceled mid-session, close the conn to unblock any pending
	// read or write.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: client: %w", err)
	}
	defer c.Close()

	if err := c.Hello(localhostName()); err != nil {
		return fmt.Errorf("smtp: hello: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{
			ServerName:         s.cfg.Host,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify, // #nosec G402 dev-only path
			MinVersion:         tls.VersionTLS12,
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}

	if err := c.Mail(fromAddr.Address); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	for _, t := range to {
		addr, _ := mail.ParseAddress(t)
		if err := c.Rcpt(addr.Address); err != nil {
			return fmt.Errorf("smtp: rcpt %s: %w", t, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	msg := buildMessage(s.cfg.From, to, subject, textBody)
	if _, err := wc.Write(msg); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: data close: %w", err)
	}
	return c.Quit()
}

// buildMessage assembles an RFC 5322 plain-text message with required headers.
func buildMessage(from string, to []string, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "Content-Transfer-Encoding: 8bit\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func localhostName() string {
	if h, err := net.LookupAddr("127.0.0.1"); err == nil && len(h) > 0 {
		return strings.TrimSuffix(h[0], ".")
	}
	return "localhost"
}
