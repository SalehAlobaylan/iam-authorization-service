package services

import (
	"fmt"
	"log"
	"net/smtp"

	"github.com/yourusername/iam-authorization-service/src/config"
)

// EmailSender abstracts email delivery so it can be swapped (SMTP, SendGrid, mock).
type EmailSender interface {
	Send(to, subject, body string) error
}

// SMTPEmailSender sends emails via SMTP.
type SMTPEmailSender struct {
	host     string
	port     string
	from     string
	password string
}

func NewSMTPEmailSender(cfg config.EmailConfig) *SMTPEmailSender {
	return &SMTPEmailSender{
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		from:     cfg.FromAddress,
		password: cfg.SMTPPassword,
	}
}

func (s *SMTPEmailSender) Send(to, subject, body string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.from, to, subject, body)

	var auth smtp.Auth
	if s.password != "" {
		auth = smtp.PlainAuth("", s.from, s.password, s.host)
	}

	addr := fmt.Sprintf("%s:%s", s.host, s.port)
	return smtp.SendMail(addr, auth, s.from, []string{to}, []byte(msg))
}

// LogEmailSender deliberately does not print recipients, bodies, or links. Those
// values contain personal data and bearer credentials even in development logs.
type LogEmailSender struct{}

func NewLogEmailSender() *LogEmailSender {
	return &LogEmailSender{}
}

func (s *LogEmailSender) Send(to, subject, body string) error {
	log.Printf("[email_delivery] provider=development result=suppressed")
	return nil
}
