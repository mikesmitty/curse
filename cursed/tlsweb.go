package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func tlsCertHandler(w http.ResponseWriter, r *http.Request, conf *config) {
	// Set up some useful info for logging
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) == 0 {
		log.Print("critical error, could not get client IP from request")
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}
	ip := parts[0]
	un := "-"

	// Start up our logger
	logger := newLog(conf, ip, "tls", "")

	// Load our form parameters into a struct
	p, err := getJSONParams(r)
	if err != nil {
		msg := fmt.Sprintf("bad json in request: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "bad request", code)
		return
	}

	// Update our logger
	logger.rip = p.UserIP

	// Get our user/pass from basic auth
	user, pass, ok := r.BasicAuth()
	if !ok {
		msg := "client basic auth failure"
		code := http.StatusUnauthorized
		logger.req(un, code, msg)
		http.Error(w, "not authorized", code)
		return
	}
	un = user

	// Check the credentials
	ok, err = pwauth(conf, user, pass)
	if !ok {
		msg := fmt.Sprintf("authorization failure: %v", err)
		code := http.StatusUnauthorized
		logger.req(un, code, msg)
		http.Error(w, "not authorized", code)
		return
	}

	// Make sure we have everything we need from our parameters
	err = validateTLSParams(p, conf)
	if err != nil {
		msg := fmt.Sprintf("invalid parameters: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "invalid parameters", code)
		return
	}

	// Decode our pem-encapsulated CSR
	csrBlock, _ := pem.Decode([]byte(p.CSR))
	if csrBlock == nil {
		msg := fmt.Sprintf("failed to decode csr: '%v'", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "invalid csr", code)
		return
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		msg := fmt.Sprintf("failed to parse CSR: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "invalid csr", code)
		return
	}

	// Validate the CSR signature
	err = csr.CheckSignature()
	if err != nil {
		msg := fmt.Sprintf("failed to check csr signature: %v", err)
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "invalid csr", code)
		return
	}

	// Check if our username received matches the CSR name
	if conf.ForceUserMatch && csr.Subject.CommonName != p.BastionUser {
		msg := "csr commonname field does not match logged-in user, denying request"
		code := http.StatusBadRequest
		logger.req(un, code, msg)
		http.Error(w, "invalid csr", code)
		return
	}

	// Sign the CSR
	cert, rawCert, err := signTLSClientCert(conf, csr)
	if err != nil {
		msg := fmt.Sprintf("error signing client cert: %v", err)
		code := http.StatusInternalServerError
		logger.req(un, code, msg)
		http.Error(w, "server error", code)
		return
	}

	// Parse the DER formatted cert
	c, err := x509.ParseCertificate(rawCert)
	if err != nil {
		msg := fmt.Sprintf("error parsing raw certificate: %v", err)
		code := http.StatusInternalServerError
		logger.req(un, code, msg)
		http.Error(w, "server error", code)
		return
	}

	// Get a public key fingerprint
	fp := tlsCertFP(c)

	// Generate our log entry
	keyID := fmt.Sprintf("user[%s] from[%s] serial[%d] fingerprint[%s]", p.BastionUser, p.UserIP, c.SerialNumber, fp)

	// Log the request
	code := http.StatusOK
	logger.req(un, code, keyID)

	w.Write(cert)
}

func validateTLSParams(p httpParams, conf *config) error {
	if !conf.userRegex.MatchString(p.BastionUser) {
		return fmt.Errorf("username is invalid: |%s|", p.BastionUser)
	}
	if p.CSR == "" {
		return fmt.Errorf("csr missing from request")
	}
	if conf.RequireClientIP && !validIP(p.UserIP) {
		return fmt.Errorf("invalid userIP: |%s|", p.UserIP)
	}

	return nil
}
