package daemon

import (
	"fmt"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/authentication"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/authorization"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/persistence"
	"log"
	"net/http"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

type DaemonConfig struct {
	ListenPort int
	ListenIP string
	BlacklistUpdateFreq int
	LoginSessionCleanupFreq int
}

func NewDefaultConfig() DaemonConfig {
	return DaemonConfig{
		ListenPort: 8080,
		ListenIP: "0.0.0.0",
		BlacklistUpdateFreq: 30,
		LoginSessionCleanupFreq: 300,
	}
}

type RedisConfig struct {
	Address string
	Password string
}

type LoginDaemon struct {
	config DaemonConfig
	authN authentication.AuthNController
	authZ authorization.AuthZController
	keystore persistence.Keystore
	r *mux.Router
}

func New(config DaemonConfig, authNConf authentication.AuthNConfig, authZConf authorization.AuthZConfig, redis RedisConfig) (LoginDaemon, error) {
	keys, err := persistence.New(redis.Address, redis.Password)
	if err != nil {
		return LoginDaemon{}, errors.Wrap(err, "keystore initialization failed.")
	}

	authNControl, err := authentication.New(authNConf, &keys)
	if err != nil {
		return LoginDaemon{}, errors.Wrap(err, "Authentication controller setup failed.")
	}

	authZControl, err := authorization.New(authZConf, &authNControl, &keys)
	if err != nil {
		return LoginDaemon{}, errors.Wrap(err, "Authorization controller setup failed.")
	}

	return LoginDaemon{
		config: config,
		authN: authNControl,
		authZ: authZControl,
		keystore: keys,
	}, nil
}

func (s *LoginDaemon) Initialize() {
	wh := s.newWildcardHandler()

	router := mux.NewRouter()
	router.HandleFunc("/healthz", HealthHandler).Methods(http.MethodGet)
	router.HandleFunc("/login/oidc", s.HandleOIDCRedirect).Methods(http.MethodGet)
	router.HandleFunc("/login", s.LoginHandler).Methods(http.MethodGet)
	router.HandleFunc("/logout", s.LogoutHandler).Methods(http.MethodGet)
	router.PathPrefix("/").Handler(wh)

	s.r = router

	s.keystore.ScheduleBlacklistUpdater(s.config.BlacklistUpdateFreq)
	s.keystore.ScheduleLoginSessionCleaner(s.config.LoginSessionCleanupFreq)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *LoginDaemon) LoginHandler(w http.ResponseWriter, r *http.Request) {
	s.authN.BeginOIDCLogin(w, r, "/")
}

func (s *LoginDaemon) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	s.authN.LogoutSession(w, r)
}

// Wildcardhandler to provide ServeHTTP method required for Go's handlers
type wildcardHandler struct {
	daemon *LoginDaemon
}

func (wh *wildcardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wh.daemon.authZ.AuthReqHandler(w, r)
}

func (s *LoginDaemon) newWildcardHandler() *wildcardHandler {
	return &wildcardHandler{
		daemon: s,
	}
}

func (s *LoginDaemon) HandleOIDCRedirect(w http.ResponseWriter, r *http.Request) {
	s.authN.OIDCHandler(w, r)
}

func (s *LoginDaemon) Start() {
	listenAddr := fmt.Sprintf("%s:%d", s.config.ListenIP, s.config.ListenPort)
	log.Println("Starting web server at", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, handlers.CORS()(s.r)))
}

