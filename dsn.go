package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type AuthType uint8

const (
	AuthTypeUndefined AuthType = iota
	AuthTypeAPIKey
	AuthTypeBearer
)

const (
	pathRetrieveDSN   = "/api/0/projects/{org}/{app}/keys/"
	pathCreateProject = "/api/0/teams/{org}/{team}/projects/"
)

var (
	ErrEmptyToken      = errors.New("sentry token is not set")
	ErrEmptyOrgName    = errors.New("sentry org name is not set")
	ErrEmptyTeamName   = errors.New("sentry team name is empty")
	ErrEmptyAppName    = errors.New("sentry app name is empty")
	ErrInvalidAuthType = errors.New("invalid auth type")
)

var nameRe = regexp.MustCompile(`[^a-zA-Z]`)

type requestOptions struct {
	path   string
	method string
	body   io.Reader
}

type sentryOptions struct {
	token string
	org   string
	team  string
	app   string
	auth  AuthType
}

type sentryDSN struct {
	Public string `json:"public"`
}

type sentryKey struct {
	Active bool      `json:"isActive"`
	DSN    sentryDSN `json:"dsn"`
}

type createKeyRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type Error struct {
	Code int
	Body []byte
}

func (e Error) Error() string {
	return fmt.Sprintf("unexpected sentry response code %d", e.Code)
}

type Client interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

type DSN struct {
	cl      Client
	baseURI string
}

func NewDSN(cl Client, baseURI string) *DSN {
	rand.Seed(time.Now().UnixNano())

	return &DSN{cl: cl, baseURI: baseURI}
}

func (d *DSN) Get(ctx context.Context) (string, error) {
	opts, err := fetchOpts()
	if err != nil {
		return "", fmt.Errorf("fetch options: %w", err)
	}

	dsn, err := d.fetchDSN(ctx, opts)
	if err != nil {
		var se Error
		if !errors.As(err, &se) {
			return "", fmt.Errorf("fetch dsn: %w", err)
		}
	}

	if dsn != "" {
		return dsn, nil
	}

	dsn, err = d.createDSN(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("create dsn: %w", err)
	}

	return dsn, nil
}

func (d *DSN) fetchDSN(ctx context.Context, opts *sentryOptions) (string, error) {
	req, err := d.buildRequest(ctx, &requestOptions{
		path:   pathRetrieveDSN,
		method: http.MethodGet,
	}, opts)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	body, err := d.execRequest(req, http.StatusOK)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}

	var keys []sentryKey

	err = json.Unmarshal(body, &keys)
	if err != nil {
		return "", fmt.Errorf("unmarshal answer: %w", err)
	}

	for _, key := range keys {
		if key.Active {
			return key.DSN.Public, nil
		}
	}

	return "", nil
}

func (d *DSN) createDSN(ctx context.Context, opts *sentryOptions) (string, error) {
	var b bytes.Buffer

	enc := json.NewEncoder(&b)

	err := enc.Encode(createKeyRequest{Name: opts.app, Slug: opts.app})
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}

	req, err := d.buildRequest(ctx, &requestOptions{
		path:   pathCreateProject,
		method: http.MethodPost,
		body:   bytes.NewReader(b.Bytes()),
	}, opts)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}

	_, err = d.execRequest(req, http.StatusCreated)
	if err != nil {
		return "", fmt.Errorf("execute request: %w", err)
	}

	return d.fetchDSN(ctx, opts)
}

func (d *DSN) buildRequest(
	ctx context.Context,
	reqOpts *requestOptions,
	sentryOpts *sentryOptions,
) (*http.Request, error) {
	if sentryOpts.auth == AuthTypeUndefined {
		return nil, ErrInvalidAuthType
	}

	parsed, err := url.Parse(d.baseURI)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	path := reqOpts.path

	placeholders := map[string]string{
		"org":  sentryOpts.org,
		"team": sentryOpts.team,
		"app":  sentryOpts.app,
	}

	for k, v := range placeholders {
		path = strings.Replace(path, "{"+k+"}", v, 1)
	}

	parsed.Path = path

	if sentryOpts.auth == AuthTypeAPIKey {
		parsed.User = url.User(sentryOpts.token)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		reqOpts.method,
		parsed.String(),
		reqOpts.body,
	)
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}

	trace := &httptrace.ClientTrace{
		DNSDone: func(di httptrace.DNSDoneInfo) {
			fmt.Printf("* DNS %v → %v\n", req.Host, di.Addrs)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Printf("* Connect done %v → %v %v\n", network, addr, err)
		},
		GotConn: func(ci httptrace.GotConnInfo) {
			fmt.Printf("* Connection local=%v remote=%v", ci.Conn.LocalAddr(), ci.Conn.RemoteAddr())
			if ci.Reused {
				fmt.Printf(" (reused)")
			}
			if ci.WasIdle {
				fmt.Printf(" (idle %v)", ci.IdleTime)
			}
			fmt.Println()
		},
		PutIdleConn: func(err error) {
			fmt.Printf("* Put idle connection: %v\n", err)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	req.Header.Add("Content-Type", "application/json")

	if sentryOpts.auth == AuthTypeBearer {
		req.Header.Add("Authorization", "Bearer "+sentryOpts.token)
	}

	return req, nil
}

func (d *DSN) execRequest(req *http.Request, expectedStatus int) ([]byte, error) {
	resp, err := d.cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read answer: %w", err)
	}

	log.Printf("* Response %s request to %s\n\t%s\n", req.Method, req.URL, body)

	if resp.StatusCode != expectedStatus {
		return nil, Error{Code: resp.StatusCode, Body: body}
	}

	return body, nil
}

func fetchOpts() (*sentryOptions, error) {
	token, ok := os.LookupEnv("SENTRY_TOKEN")
	if !ok {
		return nil, ErrEmptyToken
	}

	orgName, ok := os.LookupEnv("SENTRY_ORG_NAME")
	if !ok {
		return nil, ErrEmptyOrgName
	}

	teamName, ok := os.LookupEnv("SENTRY_TEAM_NAME")
	if !ok {
		return nil, ErrEmptyTeamName
	}

	appName := randomString(6)

	orgName = strings.ToLower(nameRe.ReplaceAllString(orgName, ""))
	teamName = strings.ToLower(nameRe.ReplaceAllString(teamName, ""))
	appName = strings.ToLower(nameRe.ReplaceAllString(appName, ""))

	var authType AuthType

	authTypeName := os.Getenv("SENTRY_AUTH_TYPE")

	switch authTypeName {
	case "api_key":
		authType = AuthTypeAPIKey
	case "bearer":
		authType = AuthTypeBearer
	default:
		authType = AuthTypeAPIKey
	}

	return &sentryOptions{
		token: token,
		org:   orgName,
		team:  teamName,
		app:   appName,
		auth:  authType,
	}, nil
}

func randomString(n int) string {
	var letterRunes = []rune("ABCDEFGHIJKLMNOPQRST")

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(b)
}
