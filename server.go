package main

import (
	"github.com/caiyeon/goldfish/handlers"
	"github.com/caiyeon/goldfish/vault"
	"github.com/gorilla/csrf"
	"github.com/gorilla/securecookie"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"

	"golang.org/x/crypto/acme/autocert"
)

var devMode = vault.DevMode

func main() {
	e := echo.New()

	// thanks mozilla (for let's encrypt)
	e.AutoTLSManager.Cache = autocert.DirCache("/var/www/.cache")
	e.AutoTLSManager.HostPolicy = autocert.HostWhitelist("vault-ui.io")

	// middleware
	e.Use(middleware.HTTPSRedirectWithConfig(middleware.RedirectConfig{
		Code: 301,
	}))
	// middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(echo.WrapMiddleware(
		csrf.Protect(
			// Generate a new encryption key for cookies each launch
			// invalidating previous goldfish instance's cookies is purposeful
			[]byte(securecookie.GenerateRandomKey(32)),
			// when devMode is false, cookie will only be sent through https
			csrf.Secure(!devMode),
		)))

	// file routing
	e.Static("/", "public")

	// API routing - wrapper around vault API
	e.GET("/api/health", handlers.VaultHealth())

	e.GET("/api/login/csrf", handlers.FetchCSRF())
	e.POST("/api/login", handlers.Login())
	e.POST("/api/login/renew-self", handlers.RenewSelf())

	e.GET("/api/users", handlers.GetUsers())
	e.GET("/api/users/csrf", handlers.FetchCSRF())
	e.GET("/api/tokencount", handlers.GetTokenCount())
	e.GET("/api/users/role", handlers.GetRole())
	e.GET("/api/users/listroles", handlers.ListRoles())
	e.POST("/api/users/revoke", handlers.DeleteUser())
	e.POST("/api/users/create", handlers.CreateUser())

	e.GET("/api/policy", handlers.GetPolicy())
	e.DELETE("/api/policy", handlers.DeletePolicy())

	e.GET("/api/policy/request", handlers.GetPolicyRequest())
	e.POST("/api/policy/request", handlers.AddPolicyRequest())
	e.POST("/api/policy/request/update", handlers.UpdatePolicyRequest())
	e.DELETE("/api/policy/request/:id", handlers.DeletePolicyRequest())

	e.GET("/api/transit", handlers.TransitInfo())
	e.POST("/api/transit/encrypt", handlers.EncryptString())
	e.POST("/api/transit/decrypt", handlers.DecryptString())

	e.GET("/api/mounts", handlers.GetMounts())
	e.GET("/api/mounts/:mountname", handlers.GetMount())
	e.POST("/api/mounts/:mountname", handlers.ConfigMount())

	e.GET("/api/secrets", handlers.GetSecrets())
	e.POST("/api/secrets", handlers.PostSecrets())

	e.GET("/api/bulletins", handlers.GetBulletins())

	if (devMode) {
		// start the server in HTTP. DO NOT USE THIS IN PRODUCTION!!
		e.Logger.Fatal(e.Start("127.0.0.1:8000"))

	} else {
		// echo will automatically request certificate and use it
		e.Logger.Fatal(e.StartAutoTLS(":443"))
	}
}