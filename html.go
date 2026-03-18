package main

import (
	"html/template"
	"net/http"
)

// works i guess? don't see the need for a real template for now.

var continueTemplate = template.Must(template.New("continue").Parse(`<!doctype html>
<meta charset="utf-8">
<title>Continue from oidc.dp42ik</title>
<h1>Continue to {{.DisplayName}}</h1>
<form method="POST" action="{{.Action}}">
	<input type="hidden" name="ticket" value="{{.Ticket}}">
	<button type="submit" autofocus>Continue</button>
</form>
`))

func writeContinuePage(w http.ResponseWriter, svc ServiceConfig, ticket string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; form-action "+svc.Origin+"; frame-ancestors 'none'; base-uri 'none'",
	)
	w.WriteHeader(http.StatusOK)
	_ = continueTemplate.Execute(w, struct {
		DisplayName string
		Action      string
		Ticket      string
	}{
		DisplayName: svc.DisplayName,
		Action:      svc.Origin + svc.ConsumePath,
		Ticket:      ticket,
	})
}

func respondError(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}
