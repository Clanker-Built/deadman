package admin

import (
	"context"

	"github.com/gcottrell/deadman/control/internal/notify"
	"github.com/gcottrell/deadman/control/internal/store"
)

// mailSettingsLoader adapts store.GetServerSettings to notify.SettingsLoader.
type mailSettingsLoader struct {
	store *store.Store
}

// NewMailSettingsLoader returns a loader that reads the server_settings
// singleton for SMTP fields.
func NewMailSettingsLoader(s *store.Store) notify.SettingsLoader {
	return &mailSettingsLoader{store: s}
}

func (m *mailSettingsLoader) LoadSMTP(ctx context.Context) (notify.SMTPDBRow, error) {
	ss, err := store.GetServerSettings(ctx, m.store.Pool)
	if err != nil {
		return notify.SMTPDBRow{}, err
	}
	row := notify.SMTPDBRow{
		Host:            ss.SMTPHost,
		Port:            ss.SMTPPort,
		Username:        ss.SMTPUsername,
		PasswordWrapped: ss.SMTPPasswordWrapped,
		From:            ss.SMTPFrom,
	}
	b := ss.SMTPInsecureSkip
	row.InsecureSkip = &b
	return row, nil
}
