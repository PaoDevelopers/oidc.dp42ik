package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ticketVersion = 1
	ticketType    = "web1 Ts"
	ticketSize    = int(unsafe.Sizeof(ticketPlaintext{}))
)

type ticketPlaintext struct { // use byte here for alignment
	Version   byte
	Type      [8]byte
	ServiceID [64]byte
	UserID    [64]byte
	IssuedAt  [8]byte
	ExpiresAt [8]byte
	TicketID  [16]byte
	AuthCtx   [64]byte
}

type ServiceConfig struct {
	ID          string
	Origin      string
	ConsumePath string
	KeyID       byte
	Key         []byte
	DisplayName string
	TTL         time.Duration
}

func userIDFromEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" {
		return "", errors.New("invalid email address")
	}
	if domain != strings.ToLower(allowedEmailDomain) {
		return "", errors.New("invalid email address domain-part")
	}
	return local, nil
}

func issueTicket(svc ServiceConfig, userID, authCtx string) ([]byte, string, error) {
	plain, ticketID, err := marshalTicket(svc.ID, userID, time.Now(), svc.TTL, authCtx)
	if err != nil {
		return nil, "", err
	}

	aead, err := chacha20poly1305.NewX(svc.Key)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}

	aad := append([]byte("web1"), []byte(svc.ID)...)
	sealed := aead.Seal(nil, nonce, plain, aad)

	wire := make([]byte, 1+len(nonce)+len(sealed))
	wire[0] = svc.KeyID
	copy(wire[1:], nonce)
	copy(wire[1+len(nonce):], sealed)
	return wire, ticketID, nil
}

func marshalTicket(serviceID, userID string, now time.Time, ttl time.Duration, authCtx string) ([]byte, string, error) {
	if len(serviceID) > 64 || len(userID) > 64 || len(authCtx) > 64 {
		return nil, "", errors.New("ticket field too long")
	}

	issuedAt, err := unixSeconds(now)
	if err != nil {
		return nil, "", err
	}
	expiresAt, err := unixSeconds(now.Add(ttl))
	if err != nil {
		return nil, "", err
	}

	var ticket ticketPlaintext
	ticket.Version = ticketVersion
	copy(ticket.Type[:], ticketType)
	copy(ticket.ServiceID[:], serviceID)
	copy(ticket.UserID[:], userID)
	binary.BigEndian.PutUint64(ticket.IssuedAt[:], issuedAt)
	binary.BigEndian.PutUint64(ticket.ExpiresAt[:], expiresAt)
	copy(ticket.AuthCtx[:], authCtx)

	if _, err := rand.Read(ticket.TicketID[:]); err != nil {
		return nil, "", err
	}

	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(&ticket)), ticketSize)), hex.EncodeToString(ticket.TicketID[:]), nil
}

func unixSeconds(t time.Time) (uint64, error) {
	secs := t.Unix()
	if secs < 0 {
		return 0, fmt.Errorf("unix time before epoch: %d", secs)
	}
	return uint64(secs), nil
}
