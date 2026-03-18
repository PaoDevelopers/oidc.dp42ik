package main

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

func routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /login", handleLogin)
	mux.HandleFunc("POST /auth", handleAuth)
	return mux
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	if svc := r.URL.Query().Get("svc"); svc != service.ID {
		respondError(w, http.StatusBadRequest, "Bad Request\nUnknown service")
		return
	}

	http.Redirect(w, r, buildAuthorizationURL(service.ID), http.StatusFound)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		respondError(w, http.StatusBadRequest, "Bad Request\nMalformed form")
		return
	}

	if extErr := r.PostFormValue("error"); extErr != "" {
		desc := r.PostFormValue("error_description")
		slog.Warn("oidc provider returned error",
			slog.String("error", extErr),
			slog.String("error_description", desc),
		)
		respondError(w, http.StatusBadRequest, "Bad Request\nExternal error")
		return
	}

	idToken := r.PostFormValue("id_token")
	if idToken == "" {
		respondError(w, http.StatusBadRequest, "Bad Request\nID token expected but not found")
		return
	}

	claims, err := verifyIDToken(r.Context(), idToken)
	if err != nil {
		if tokenErr, ok := errors.AsType[*tokenValidationError](err); ok {
			respondError(w, http.StatusBadRequest, "Bad Request\n"+tokenErr.PublicMessage)
			return
		}
		slog.Error("token verification failed", slog.Any("error", err))
		respondError(w, http.StatusBadRequest, "Bad Request\nInvalid JWT")
		return
	}

	userID, err := userIDFromEmail(claims.Email)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized\n"+err.Error())
		return
	}

	wire, ticketID, err := issueTicket(service, userID, "OIDC")
	if err != nil {
		slog.Error("ticket issuance failed", slog.Any("error", err))
		respondError(w, http.StatusInternalServerError, "Internal Server Error\nCannot issue ticket")
		return
	}

	slog.Info("ticket issued",
		slog.String("service_id", service.ID),
		slog.String("user_id", userID),
		slog.String("email", strings.ToLower(claims.Email)),
		slog.String("ticket_id", ticketID),
	)

	writeContinuePage(w, service, base64.StdEncoding.EncodeToString(wire))
}
