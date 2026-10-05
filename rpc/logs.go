package rpc

import "errors"

// LogLevels is the result of wbft_logLevels and admin_wbftSetLogLevels: the
// log settings in force (observe.md 7.1).
type LogLevels struct {
	// Level is the base level; Modules the explicit module levels.
	Level   string            `json:"level"`
	Modules map[string]string `json:"modules"`
	// Effective is the level of every module.
	Effective map[string]string `json:"effective"`
	// Source and At tell where and when the settings were last applied
	// (config or rpc; RFC 3339).
	Source string `json:"source"`
	At     string `json:"at,omitempty"`
}

// SetLogLevelsRequest is the argument of admin_wbftSetLogLevels: a new base
// level (absent: unchanged) and module levels; a null module level removes
// that module's entry. With Replace the module entries replace all
// explicit entries instead of being merged into them.
type SetLogLevelsRequest struct {
	Level   *string            `json:"level"`
	Modules map[string]*string `json:"modules"`
	Replace bool               `json:"replace"`
}

// AdminBackend changes the node's log settings.
type AdminBackend interface {
	SetLogLevels(req SetLogLevelsRequest) (LogLevels, error)
}

// AdminAPIs returns the admin namespace of wbft: admin_wbftSetLogLevels.
// The application registers it only where administrative methods belong
// (IPC, or an authenticated endpoint): turning logs on can fill the disk,
// and turning them off can remove a record.
func AdminAPIs(b AdminBackend) []API {
	return []API{{Namespace: "admin", Service: &AdminService{b: b}}}
}

// AdminService is the admin namespace of wbft.
type AdminService struct{ b AdminBackend }

// ErrNoRequest is returned for a call without a request object.
var ErrNoRequest = errors.New("wbft: missing request")

// WbftSetLogLevels is admin_wbftSetLogLevels: it applies the request and
// returns the settings in force; an unknown module or level changes
// nothing and returns an error.
func (s *AdminService) WbftSetLogLevels(req *SetLogLevelsRequest) (LogLevels, error) {
	if req == nil {
		return LogLevels{}, ErrNoRequest
	}
	return s.b.SetLogLevels(*req)
}

// LogLevels is wbft_logLevels: the log settings in force.
func (s *Service) LogLevels() LogLevels { return s.b.LogLevels() }
