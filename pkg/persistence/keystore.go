package persistence

import (
	"encoding/json"
	"github.com/ajmyyra/ambassador-auth-oidc/pkg/util"
	"github.com/go-redis/redis"
	"github.com/pkg/errors"
	"log"
	"reflect"
	"time"
)

type LoginSession struct {
	State    string
	Validity time.Time
	OrigURL  string
}

type BlacklistItem struct {
	Key        string    `json:"key"`
	JWTHash    string    `json:"hash"`
	Expiration time.Time `json:"exp"`
}

type Keystore struct {
	redis *redis.Client
	blacklist []BlacklistItem
	sessions []LoginSession
}

func New(redisAddr string, redisPwd string) (Keystore, error) {
	store := Keystore{
		redis:     nil,
		blacklist: []BlacklistItem{},
	}
	if redisAddr != "" {
		redisDb := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: redisPwd,
			DB:       0,
		})

		_, err := redisDb.Ping().Result()
		if err != nil {
			return Keystore{}, errors.Wrap(err, "Problem connecting to Redis database")
		}

		store.redis = redisDb
		log.Println("Using Redis at", redisAddr)
		store.updateBlacklist()
	}

	return store, nil
}

func (s *Keystore) ScheduleBlacklistUpdater(seconds int) {
	s.updateBlacklist()
	if s.redis != nil {
		go s.blacklistUpdater(seconds)
		log.Println("Blacklist updater scheduled to run every", seconds, "seconds.")
	}
}

func (s *Keystore) blacklistUpdater(seconds int) {
	for {
		time.Sleep(time.Duration(seconds) * time.Second)
		s.updateBlacklist()
	}
}

func (s *Keystore) ScheduleLoginSessionCleaner(seconds int) {
	go s.loginSessionCleaner(seconds)
	log.Println("Login session cleaner scheduled to run every", seconds, "seconds.")
}

func (s *Keystore) loginSessionCleaner(seconds int) {
	for {
		time.Sleep(time.Duration(seconds) * time.Second)
		s.removeOldLoginSessions()
	}
}

func (s *Keystore) CreateLoginSession(origUrl string) (string, error) {
	var state = util.CreateNonce(8)
	session := LoginSession{
		State: state,
		Validity: time.Now().Add(time.Hour),
		OrigURL: origUrl,
	}

	if s.redis != nil {
		jsonSession, err := json.Marshal(session)
		if err != nil {
			log.Printf("Problem converting login session to JSON: %v", err)
			return "", err
		}

		if err := s.redis.Set("state-"+state, string(jsonSession), time.Hour).Err(); err != nil {
			return "", err
		}
	} else {
		s.sessions = append(s.sessions, session)
	}

	return state, nil
}

func (s *Keystore) FindLoginSession(state string) (*LoginSession, error) {
	if s.redis != nil {
		jsonLoginSession, err := s.redis.Get("state-" + state).Result()
		if err != nil {
			if err.Error() == "redis: nil" { // State didn't exist, redirecting to new login
				return nil, nil
			}

			return nil, errors.New("Error fetching state from DB.")
		}

		var session LoginSession
		if err = json.Unmarshal([]byte(jsonLoginSession), &session); err != nil {
			return nil, errors.Wrap(err, "Problem converting session JSON to original model.")
		}

		return &session, nil

	} else {
		for _, elem := range s.sessions {
			if elem.State == state {
				return &elem, nil
			}
		}
	}

	return nil, nil
}

func (s *Keystore) RemoveLoginSession(state string) {
	if s.redis != nil {
		if err := s.redis.Del("state-" + state).Err(); err != nil {
			log.Println("WARNING: Unable to remove state from DB,", err.Error())
		}
	}

	for i, elem := range s.sessions {
		if elem.State == state {
			s.sessions[len(s.sessions)-1], s.sessions[i] = s.sessions[i], s.sessions[len(s.sessions)-1]
			s.sessions = s.sessions[:len(s.sessions)-1]
			return
		}
	}

	log.Println("WARNING: Tried to delete a nonexistent local session, nothing found.")
}

func (s *Keystore) removeOldLoginSessions() {
	for _, elem := range s.sessions {
		if elem.Validity.Before(time.Now()) {
			log.Println("Removing expired state", elem.State, "from active login sessions.")
			s.RemoveLoginSession(elem.State)
		}
	}
}

func (s *Keystore) AddToBlacklist(token string, exp time.Time) (bool, error) {
	blKey := util.CreateNonce(8)
	blItem := BlacklistItem{Key: blKey, JWTHash: util.HashString(token), Expiration: exp}

	if s.redis != nil {
		blJSON, err := json.Marshal(blItem)
		if err != nil {
			panic(err)
		}

		if err = s.redis.HSet("blacklist", blKey, string(blJSON)).Err(); err != nil {
			return false, err
		}
	}

	s.blacklist = append(s.blacklist, blItem)
	return true, nil
}

func (s *Keystore) updateBlacklist() {
	if s.redis == nil {
		log.Println("Redis not configured, unable to update blacklist.")
		return
	}
	res, err := s.redis.HVals("blacklist").Result()
	if err != nil {
		panic(err)
	}

	var newBlacklist []BlacklistItem

	for _, i := range res {
		var blItem BlacklistItem

		if err = json.Unmarshal([]byte(i), &blItem); err != nil {
			panic(err)
		}

		if blItem.Expiration.Before(time.Now()) {
			log.Println("Removing expired token", blItem.Key, "from blacklist.")
			err = s.redis.HDel("blacklist", blItem.Key).Err()
			if err != nil {
				panic(err)
			}
			continue
		}

		newBlacklist = append(newBlacklist, blItem)
	}

	if !reflect.DeepEqual(s.blacklist, newBlacklist) {
		s.blacklist = newBlacklist
		log.Println("Blacklist changes in Redis, local blacklist recreated.")
	}
}

func (s *Keystore) CheckBlacklist(rawToken string) bool {
	jwtHash := util.HashString(rawToken)
	for _, elem := range s.blacklist {
		if jwtHash == elem.JWTHash {
			return true
		}
	}

	return false
}

