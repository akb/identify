package http

//type NewTokenResponse struct {
//	Access  string `json:"access"`
//	Refresh string `json:"refresh"`
//}

//const (
//	tokenContextKey = contextKey("token")
//)

//func TokenFromContext(ctx context.Context) (token.Token, error) {
//	v := ctx.Value(tokenContextKey)
//	if v == nil {
//		return nil, fmt.Errorf("Token not found in request context")
//	}
//	return v.(token.Token), nil
//}

//func (p AuthProvider) RequireTokenAuth(h http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		authHeader := r.Header.Get("Authorization")
//		splitHeader := strings.Split(authHeader, " ")
//		if len(splitHeader) < 2 {
//			p.unauthorizedToken(w)
//			return
//		}
//
//		token, err := p.TokenStore.Parse(splitHeader[1])
//		if err != nil || !token.Valid() {
//			p.unauthorizedToken(w)
//			return
//		}
//
//		id := token.Identity()
//		if id == "" {
//			p.unauthorizedToken(w)
//			return
//		}
//
//		identity, err := p.IdentityStore.Get(id)
//		if err != nil {
//			p.unauthorizedToken(w)
//			return
//		}
//
//		r = r.WithContext(context.WithValue(r.Context(), identityContextKey, identity))
//		h.ServeHTTP(w, r)
//	})
//}

//func (p AuthProvider) unauthorizedToken(w http.ResponseWriter) {
//	http.Error(w, "unauthorized", http.StatusUnauthorized)
//}

//func (a api) newToken(w http.ResponseWriter, r *http.Request) {
//	identity, err := IdentityFromContext(r.Context())
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	access, refresh, err := a.TokenStore.New(identity)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	response, err := json.Marshal(NewTokenResponse{
//		Access:  access.String(),
//		Refresh: refresh.String(),
//	})
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	w.Header().Set("Content-Type", "application/json")
//	w.Write(response)
//}
//
//func (a api) deleteToken(w http.ResponseWriter, r *http.Request) {
//	token, err := TokenFromContext(r.Context())
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//
//	err = a.TokenStore.Delete(token.Identity(), token.ID())
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//	}
//}
//
