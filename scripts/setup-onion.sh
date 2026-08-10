#!/usr/bin/env bash
#
# setup-onion.sh — install Deadman on a vanilla Ubuntu host.
#
# This is a ONE-SHOT installer. Starting from a fresh Ubuntu install with
# nothing but SSH, this script will:
#
#   1. Re-exec itself under sudo if you forgot to.
#   2. Install Docker (docker.io + docker-compose-v2), Tor, Go 1.25, ufw,
#      and a few small utilities — anything missing.
#   3. Configure the host firewall (allow SSH, deny everything else).
#   4. Verify the system clock is NTP-synchronized.
#   5. Prompt for: bootstrap admin email, vault passphrases A and B,
#      backup retention, optional SMTP.
#   6. Generate random Postgres + MinIO secrets (or reuse existing ones).
#   7. Create the deadman system user + directories under /opt and /var/lib.
#   8. Build the control-plane binary from this repo.
#   9. Bring up the docker-compose stack (Postgres + 2× MinIO).
#  10. Apply DB migrations.
#  11. Install and start a Tor v3 hidden service; read back the .onion.
#  12. Write /etc/deadman/deadman.env (mode 0600, owned by deadman).
#  13. Install systemd unit + logrotate config.
#  14. Start the deadman-control service and capture the offline recovery
#      share (share 3), then verify the service is healthy (active +
#      answering on the loopback port).
#  15. Print a final report with the .onion URL and a Day-1 checklist.
#
# Idempotent in the safe sense: re-running with the same settings on the
# same host should not break an existing install. It WILL overwrite
# /etc/deadman/deadman.env if you confirm at the prompt.
#
# Defaults:
#   - Onion-only (no clearnet listener, no TLS).
#   - Single host (Postgres + MinIO + control plane + Tor all here).
#   - Vault passphrases stored in the env file at install time. To harden,
#     see docs/self-hosting.md "Day 2 hardening".
#
# Tested target: Ubuntu 24.04 LTS and 26.04 LTS. Debian 12 also works.
# Other distros print a warning and try anyway via apt; install steps that
# fail are reported clearly.
#
# Usage:
#   ./scripts/setup-onion.sh                      # auto-elevates with sudo
#   ./scripts/setup-onion.sh --non-interactive    # uses env vars
#
# In non-interactive mode, set:
#   SETUP_ADMIN_EMAIL, SETUP_VAULT_PASS_A, SETUP_VAULT_PASS_B,
#   SETUP_BACKUP_KEEP (default 14)

set -euo pipefail

# Auto-elevate. Re-exec under sudo if we're not already root, preserving
# the env-driven non-interactive variables.
if [[ "$EUID" -ne 0 ]]; then
  echo
  echo "This installer needs root to install packages and write to /etc."
  echo "Re-running under sudo (you may be prompted for your password)..."
  echo
  exec sudo --preserve-env=NON_INTERACTIVE,SETUP_ADMIN_EMAIL,SETUP_VAULT_PASS_A,SETUP_VAULT_PASS_B,SETUP_BACKUP_KEEP \
       -- "$0" "$@"
fi

# -------------------------------------------------------------------------
# Config (mostly resolved from the repo path; tweak if you've relocated).
# -------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/deadman"
STATE_DIR="/var/lib/deadman"
LOG_DIR="/var/log/deadman"
ENV_DIR="/etc/deadman"
ENV_FILE="${ENV_DIR}/deadman.env"
COMPOSE_ENV_FILE="${REPO_ROOT}/ops/docker/.env"
LOGROTATE_FILE="/etc/logrotate.d/deadman"
BIN_PATH="${INSTALL_DIR}/bin/deadman-control"
SYSTEMD_UNIT_DST="/etc/systemd/system/deadman-control.service"
TORRC_INCLUDE_DIR="/etc/tor/torrc.d"
TORRC_FILE="${TORRC_INCLUDE_DIR}/deadman.conf"
TOR_HSDIR="/var/lib/tor/deadman"
DEADMAN_USER="deadman"
LISTEN_PORT=8080
GOOSE_VERSION="v3.27.0"
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"

# -------------------------------------------------------------------------
# UI helpers.
# -------------------------------------------------------------------------

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi

step()    { printf "\n%s== %s ==%s\n" "${C_BLU}${C_BLD}" "$1" "${C_RST}"; }
info()    { printf "  %s\n" "$1"; }
ok()      { printf "  %s✓%s %s\n" "${C_GRN}" "${C_RST}" "$1"; }
warn()    { printf "  %s!%s %s\n" "${C_YEL}" "${C_RST}" "$1"; }
fail()    { printf "  %s✗ %s%s\n" "${C_RED}" "$1" "${C_RST}" >&2; exit 1; }

ask() {
  # ask "Prompt" "default" -> echoes the answer
  local prompt="$1" default="${2:-}" answer=""
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    echo "$default"
    return
  fi
  if [[ -n "$default" ]]; then
    read -r -p "    $prompt [$default]: " answer </dev/tty || answer=""
    echo "${answer:-$default}"
  else
    read -r -p "    $prompt: " answer </dev/tty
    echo "$answer"
  fi
}

ask_secret() {
  # ask_secret "Prompt"
  local prompt="$1" answer=""
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    echo ""
    return
  fi
  read -r -s -p "    $prompt: " answer </dev/tty
  echo "" >&2
  echo "$answer"
}

confirm() {
  local prompt="$1" default="${2:-N}" answer=""
  local hint
  if [[ "$default" == "Y" ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    [[ "$default" == "Y" ]]
    return $?
  fi
  read -r -p "    $prompt $hint " answer </dev/tty || answer=""
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy] ]]
}

random_passphrase() {
  # 6 hex bytes per group, 4 groups, hyphenated. ~96 bits entropy. Enough.
  local p=""
  for i in 1 2 3 4; do
    p="${p}${p:+-}$(openssl rand -hex 6)"
  done
  echo "$p"
}

random_secret() {
  # 32 random bytes, base64 (no padding, no slashes, no newlines).
  openssl rand 32 | base64 | tr -d '=+/\n' | head -c 32
}

# load_or_make_compose_env reads existing compose creds if present so re-runs
# don't break an existing stack. Otherwise generates fresh random secrets.
# Sets globals: PG_USER, PG_PASS, PG_DB, MINIO_USER, MINIO_PASS.
load_or_make_compose_env() {
  if [[ -f "$COMPOSE_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; . "$COMPOSE_ENV_FILE"; set +a
    PG_USER="${POSTGRES_USER:-}"
    PG_PASS="${POSTGRES_PASSWORD:-}"
    PG_DB="${POSTGRES_DB:-deadman}"
    MINIO_USER="${MINIO_ROOT_USER:-}"
    MINIO_PASS="${MINIO_ROOT_PASSWORD:-}"
    if [[ -n "$PG_USER" && -n "$PG_PASS" && -n "$MINIO_USER" && -n "$MINIO_PASS" ]]; then
      ok "Reusing existing compose credentials from $COMPOSE_ENV_FILE."
      return
    fi
    warn "$COMPOSE_ENV_FILE exists but is incomplete; regenerating."
  fi
  PG_USER="deadman"
  PG_PASS="$(random_secret)"
  PG_DB="deadman"
  MINIO_USER="deadman"
  MINIO_PASS="$(random_secret)"
  umask 077
  cat > "$COMPOSE_ENV_FILE" <<EOF
# Generated by setup-onion.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Read by docker-compose. Do NOT commit a populated copy to git.
POSTGRES_USER=${PG_USER}
POSTGRES_PASSWORD=${PG_PASS}
POSTGRES_DB=${PG_DB}
MINIO_ROOT_USER=${MINIO_USER}
MINIO_ROOT_PASSWORD=${MINIO_PASS}
EOF
  chmod 0600 "$COMPOSE_ENV_FILE"
  ok "Generated random credentials in $COMPOSE_ENV_FILE."
}

# -------------------------------------------------------------------------
# Pre-flight.
# -------------------------------------------------------------------------

check_os() {
  if [[ ! -r /etc/os-release ]]; then
    warn "/etc/os-release missing. Cannot detect distribution; proceeding anyway."
    return
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    ubuntu)
      ok "OS: ${PRETTY_NAME:-Ubuntu}"
      ;;
    debian)
      ok "OS: ${PRETTY_NAME:-Debian}"
      warn "Debian is supported but less tested than Ubuntu."
      ;;
    *)
      warn "OS '$PRETTY_NAME' is not Ubuntu/Debian. apt install steps may fail; if they do, install the missing packages manually and re-run."
      ;;
  esac
}

apt_install_if_missing() {
  local missing=()
  for pkg in "$@"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    info "apt installing: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
  fi
}

install_docker_if_missing() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ok "Docker present: $(docker --version 2>/dev/null | sed 's/, build.*//')"
    return
  fi
  info "Installing Docker (docker.io + docker-compose-v2 from Ubuntu archives)..."
  apt_install_if_missing docker.io docker-compose-v2
  systemctl enable --now docker >/dev/null 2>&1 || true
  # Add the invoking sudo user to the docker group so they can run
  # `docker` without sudo after a re-login. Harmless if the user is
  # root or already in the group.
  if [[ -n "${SUDO_USER:-}" ]] && [[ "$SUDO_USER" != "root" ]]; then
    if ! id -nG "$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      usermod -aG docker "$SUDO_USER"
      DOCKER_GROUP_ADDED=1
    fi
  fi
  if ! docker compose version >/dev/null 2>&1; then
    fail "Docker installed but 'docker compose' plugin not detected. Try 'apt install docker-compose-v2' manually and re-run."
  fi
  ok "Docker installed and started."
}

install_go_if_missing() {
  local need_minor=25
  if command -v go >/dev/null 2>&1; then
    local cur
    cur="$(go version 2>/dev/null | awk '{print $3}')"   # e.g. go1.25.9
    cur="${cur#go}"
    local minor
    minor="$(echo "$cur" | cut -d. -f2)"
    if [[ -n "$minor" ]] && [[ "$minor" =~ ^[0-9]+$ ]] && (( minor >= need_minor )); then
      ok "Go ${cur} present."
      return
    fi
    info "Found Go ${cur} but 1.${need_minor}+ required; downloading newer."
  else
    info "Go not found; downloading 1.25.9 from go.dev."
  fi

  local arch
  case "$(uname -m)" in
    x86_64)  arch=amd64 ;;
    aarch64) arch=arm64 ;;
    armv7l)  arch=armv6l ;;
    *) fail "Unsupported architecture for automatic Go install: $(uname -m). Install Go 1.25+ manually (https://go.dev/dl/) and re-run." ;;
  esac

  local goversion=1.25.9
  local tar=/tmp/go-${goversion}.tar.gz
  curl -fsSL "https://go.dev/dl/go${goversion}.linux-${arch}.tar.gz" -o "$tar"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tar"
  rm -f "$tar"
  ln -sf /usr/local/go/bin/go    /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  ok "Go ${goversion} installed at /usr/local/go (symlinked into /usr/local/bin)."
}

check_prereqs() {
  step "Installing prerequisites"
  apt_install_if_missing tor openssl ca-certificates curl gnupg ufw lsof jq
  install_docker_if_missing
  install_go_if_missing
  ok "All prerequisites ready."
}

check_time_sync() {
  step "Verifying host clock is synced"
  if ! command -v timedatectl >/dev/null 2>&1; then
    warn "timedatectl not present; cannot verify NTP. Make sure your clock is accurate by some other means."
    return
  fi
  local synced
  synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)"
  if [[ "$synced" == "yes" ]]; then
    ok "System clock is NTP-synchronized."
  else
    warn "System clock is NOT NTP-synchronized. The scheduler relies on accurate time."
    warn "Enable systemd-timesyncd or chrony, then re-check with 'timedatectl status'."
  fi
}

configure_firewall() {
  step "Configuring host firewall (ufw)"
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw not installed; skipping firewall configuration."
    return
  fi
  # Be careful not to lock the operator out of an SSH session.
  ufw --force default deny incoming  >/dev/null
  ufw --force default allow outgoing >/dev/null
  # Permit SSH on the standard port. Operators using a custom port need
  # to add their own ufw rule before/after.
  ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null
  # Tor outbound is allowed by default-allow-outgoing; nothing else inbound.
  if ! ufw status | grep -q "Status: active"; then
    ufw --force enable >/dev/null
    ok "ufw enabled (deny incoming, allow outgoing, SSH allowed)."
  else
    ok "ufw already active; rules updated (deny incoming, allow OpenSSH)."
  fi
  warn "If your SSH listens on a non-standard port, add a ufw rule for it NOW before logging out."
}

# -------------------------------------------------------------------------
# Prompt phase.
# -------------------------------------------------------------------------

looks_like_email() {
  # Very permissive: requires exactly one @ with non-empty parts on each
  # side and a dot somewhere after the @. Catches the common typo of
  # pasting a password into this prompt.
  [[ "$1" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]
}

prompt_settings() {
  step "Configuration"

  # Banner so the user is unambiguously past sudo. If sudo was cached
  # (no password prompt), this is the first user-visible signal that the
  # installer's own prompts are starting.
  cat <<EOF

  ${C_BLD}Sudo accepted; running as root. The next prompts come from the
  installer itself — none of them ask for your sudo password.${C_RST}

EOF

  if [[ "$NON_INTERACTIVE" == "1" ]]; then
    ADMIN_EMAIL="${SETUP_ADMIN_EMAIL:?SETUP_ADMIN_EMAIL is required in non-interactive mode}"
    PASS_A="${SETUP_VAULT_PASS_A:?SETUP_VAULT_PASS_A is required}"
    PASS_B="${SETUP_VAULT_PASS_B:?SETUP_VAULT_PASS_B is required}"
    BACKUP_KEEP="${SETUP_BACKUP_KEEP:-14}"
    SMTP_ENABLED=0
  else
    while true; do
      ADMIN_EMAIL="$(ask 'Bootstrap admin email (first login auto-promotes)')"
      if [[ -z "$ADMIN_EMAIL" ]]; then
        warn "Email is required."
        continue
      fi
      if ! looks_like_email "$ADMIN_EMAIL"; then
        warn "That doesn't look like an email (need user@host.tld). Did you mean to type something else? Re-enter."
        continue
      fi
      break
    done

    info ""
    info "Vault passphrases (two are required, one per custodian)."
    info "If you generate them now, WRITE THEM DOWN before continuing."
    if confirm "Generate two random passphrases for me?" Y; then
      PASS_A="$(random_passphrase)"
      PASS_B="$(random_passphrase)"
      printf "\n"
      printf "    %sPassphrase A:%s %s\n" "${C_BLD}" "${C_RST}" "$PASS_A"
      printf "    %sPassphrase B:%s %s\n" "${C_BLD}" "${C_RST}" "$PASS_B"
      printf "\n"
      warn "These will also live in $ENV_FILE (mode 0600). Write them on paper now."
      read -r -p "    Press Enter once you've recorded both. " _ </dev/tty
    else
      while [[ -z "${PASS_A:-}" ]]; do PASS_A="$(ask_secret 'Passphrase A')"; done
      while [[ -z "${PASS_B:-}" ]]; do PASS_B="$(ask_secret 'Passphrase B')"; done
      if [[ "$PASS_A" == "$PASS_B" ]]; then
        fail "Passphrases A and B must differ."
      fi
    fi

    BACKUP_KEEP="$(ask 'Backup retention (most-recent N kept)' '14')"
    SMTP_ENABLED=0
    if confirm "Configure SMTP now? (you can also do it later in the admin panel)" N; then
      SMTP_ENABLED=1
      SMTP_HOST="$(ask 'SMTP host (e.g. smtp.fastmail.com)')"
      SMTP_PORT="$(ask 'SMTP port' '587')"
      SMTP_USER="$(ask 'SMTP username')"
      SMTP_PASS="$(ask_secret 'SMTP password')"
      SMTP_FROM="$(ask 'SMTP from (e.g. Deadman <noreply@yourdomain.org>)')"
    fi
  fi

  if confirm "Continue with these settings? Existing $ENV_FILE will be overwritten." Y; then
    return 0
  else
    fail "Aborted by user."
  fi
}

# -------------------------------------------------------------------------
# Install steps.
# -------------------------------------------------------------------------

create_user_and_dirs() {
  step "Users and directories"
  if id -u "$DEADMAN_USER" >/dev/null 2>&1; then
    ok "User $DEADMAN_USER already exists."
  else
    useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin --user-group "$DEADMAN_USER"
    ok "Created system user $DEADMAN_USER."
  fi
  install -d -m 0750 -o "$DEADMAN_USER" -g "$DEADMAN_USER" "$STATE_DIR"
  install -d -m 0750 -o "$DEADMAN_USER" -g "$DEADMAN_USER" "$LOG_DIR"
  install -d -m 0755                                       "$INSTALL_DIR"
  install -d -m 0755                                       "$INSTALL_DIR/bin"
  install -d -m 0750                                       "$ENV_DIR"
  ok "Directories ready."
}

build_binary() {
  # Skip path: the operator dropped a prebuilt binary at $REPO_ROOT/deadman-control
  # (e.g. cross-compiled from a host with a working Go toolchain). Useful when
  # the VM's Go install hits a compiler-internal panic on x/text/runes.
  if [ -x "$REPO_ROOT/deadman-control" ]; then
    step "Using prebuilt binary at $REPO_ROOT/deadman-control"
    install -m 0755 "$REPO_ROOT/deadman-control" "$BIN_PATH"
    ok "Installed $BIN_PATH from prebuilt."
    return
  fi
  step "Building deadman-control"
  ( cd "$REPO_ROOT/control" && CGO_ENABLED=0 go build -o "$BIN_PATH" ./cmd/server )
  chmod 0755 "$BIN_PATH"
  ok "Built $BIN_PATH."
}

bring_up_stack() {
  step "Starting Postgres + MinIO (docker compose)"
  ( cd "$REPO_ROOT" && docker compose -f ops/docker/docker-compose.yml up -d )
  info "Waiting for Postgres to accept connections..."
  local tries=0
  until docker compose -f "$REPO_ROOT/ops/docker/docker-compose.yml" exec -T postgres \
        pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; do
    tries=$((tries+1))
    if (( tries > 60 )); then
      fail "Postgres did not become ready in 60 attempts."
    fi
    sleep 1
  done
  ok "Postgres ready."
}

run_migrations() {
  step "Applying database migrations"
  local dsn="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}?sslmode=disable"

  # Prefer a prebuilt goose binary at $REPO_ROOT/goose (cross-compile from a
  # host with a working Go toolchain when the VM's compiler is broken).
  if [ -x "$REPO_ROOT/goose" ]; then
    ( cd "$REPO_ROOT/control" && \
      "$REPO_ROOT/goose" -dir db/migrations postgres "$dsn" up )
    ok "Migrations applied (prebuilt goose)."
    return
  fi

  # Fallback: pipe each migration's "+goose Up" block through psql in the
  # Postgres container, then record the version in goose_db_version.
  # Triggered when `go run goose` would fail (e.g. VM compiler bug).
  if ! ( cd "$REPO_ROOT/control" && \
         go run "github.com/pressly/goose/v3/cmd/goose@${GOOSE_VERSION}" \
           -dir db/migrations postgres "$dsn" up ); then
    warn "go-run goose failed; falling back to direct psql apply"
    apply_migrations_via_psql
  fi
  ok "Migrations applied."
}

apply_migrations_via_psql() {
  local container
  container="$(docker ps --format '{{.Names}}' | grep -m1 postgres || true)"
  [ -n "$container" ] || fail "no running postgres container found"

  # Initialize goose_db_version if it doesn't exist.
  docker exec -i "$container" psql -U "$PG_USER" -d "$PG_DB" <<'SQL' >/dev/null
CREATE TABLE IF NOT EXISTS goose_db_version (
  id SERIAL PRIMARY KEY,
  version_id BIGINT NOT NULL,
  is_applied BOOLEAN NOT NULL,
  tstamp TIMESTAMP NULL DEFAULT now()
);
INSERT INTO goose_db_version (version_id, is_applied) SELECT 0, true
  WHERE NOT EXISTS (SELECT 1 FROM goose_db_version);
SQL

  for f in $(ls -1 "$REPO_ROOT/control/db/migrations"/*.sql | sort); do
    local v
    v="$(basename "$f" | cut -d_ -f1)"
    if docker exec -i "$container" psql -U "$PG_USER" -d "$PG_DB" -tAc \
         "SELECT 1 FROM goose_db_version WHERE version_id=$v AND is_applied" \
       | grep -q 1; then
      continue
    fi
    # Extract just the +goose Up block (everything between the first
    # '-- +goose Up' line and the next '-- +goose Down' line).
    awk '/-- \+goose Up/{flag=1; next} /-- \+goose Down/{flag=0} flag' "$f" \
      | docker exec -i "$container" psql -U "$PG_USER" -d "$PG_DB" -v ON_ERROR_STOP=1 \
      || fail "migration $v failed"
    docker exec -i "$container" psql -U "$PG_USER" -d "$PG_DB" -c \
      "INSERT INTO goose_db_version (version_id, is_applied) VALUES ($v, true)" \
      >/dev/null
  done
}

# -------------------------------------------------------------------------
# Tor.
# -------------------------------------------------------------------------

install_torrc() {
  step "Configuring Tor hidden service"
  local main_torrc="/etc/tor/torrc"
  if [[ ! -f "$main_torrc" ]]; then
    fail "Expected $main_torrc not found. Is Tor installed?"
  fi

  # Inline the hidden-service block directly into /etc/tor/torrc, between
  # idempotent BEGIN/END markers. We deliberately avoid /etc/tor/torrc.d
  # globbing — Tor 0.4.9+ on Ubuntu has a sandbox interaction where
  # `%include /etc/tor/torrc.d/*.conf` verifies clean but fails on actual
  # daemon start-up with "Error reading included configuration file or
  # directory: /etc/tor/torrc.d/*.conf".
  local marker_begin="# === BEGIN deadman setup-onion.sh ==="
  local marker_end="# === END deadman setup-onion.sh ==="
  if grep -qF "$marker_begin" "$main_torrc"; then
    info "Removing previous deadman block from $main_torrc."
    # Delete from BEGIN marker through END marker, inclusive.
    sed -i "/$marker_begin/,/$marker_end/d" "$main_torrc"
  fi
  # Also clean up an old torrc.d artefact from a previous failed install,
  # so re-running this script after the previous bug leaves no dangling
  # include directive.
  if [[ -f "$TORRC_FILE" ]]; then
    info "Removing stale $TORRC_FILE from a previous run."
    rm -f "$TORRC_FILE"
  fi
  if grep -qE '^[[:space:]]*%include[[:space:]]+/etc/tor/torrc\.d' "$main_torrc"; then
    info "Commenting out the broken %include directive in $main_torrc."
    sed -i 's|^\([[:space:]]*%include[[:space:]]\+/etc/tor/torrc\.d.*\)|# disabled by deadman: \1|' "$main_torrc"
  fi

  cat >> "$main_torrc" <<EOF

${marker_begin}
# Tor v3 hidden service for Deadman. Do NOT delete /var/lib/tor/deadman/
# or you will permanently lose the .onion address (back it up encrypted).
HiddenServiceDir /var/lib/tor/deadman/
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080
${marker_end}
EOF
  ok "Wrote hidden-service block into $main_torrc."

  # Restart the worker service (tor@default), not the systemd wrapper
  # (tor.service is just a meta on Debian/Ubuntu). Reloading the wrapper
  # does NOT propagate config changes to the running daemon.
  systemctl restart tor@default
  ok "Restarted tor@default."

  info "Waiting for hidden service hostname (up to 60s)..."
  local tries=0
  while [[ ! -s "$TOR_HSDIR/hostname" ]]; do
    tries=$((tries+1))
    if (( tries > 60 )); then
      echo
      echo "Last 30 lines of tor@default journal:"
      journalctl -u tor@default -n 30 --no-pager
      fail "Tor never produced $TOR_HSDIR/hostname after 60s. See output above."
    fi
    sleep 1
  done
  ONION_HOST="$(tr -d '[:space:]' < "$TOR_HSDIR/hostname")"
  ok "Hidden service: http://${ONION_HOST}"
}

# -------------------------------------------------------------------------
# Env file + systemd.
# -------------------------------------------------------------------------

write_env_file() {
  step "Writing $ENV_FILE"
  umask 077
  {
    cat <<EOF
# Generated by setup-onion.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Mode 0600, owned by ${DEADMAN_USER}:${DEADMAN_USER}.
# Edits here take effect on the next "systemctl restart deadman-control".

DEADMAN_ENV=production
DEADMAN_LISTEN_ADDR=127.0.0.1:${LISTEN_PORT}

DEADMAN_DATABASE_URL=postgres://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}?sslmode=disable

DEADMAN_S3_PRIMARY_ENDPOINT=http://127.0.0.1:9000
DEADMAN_S3_BACKUP_ENDPOINT=http://127.0.0.1:9010
DEADMAN_S3_ACCESS_KEY=${MINIO_USER}
DEADMAN_S3_SECRET_KEY=${MINIO_PASS}

DEADMAN_RP_ID=${ONION_HOST}
DEADMAN_RP_ORIGINS=http://${ONION_HOST}

DEADMAN_VAULT_PATH=${STATE_DIR}/release-vault.json
DEADMAN_SERVICE_SIGNING_KEY_PATH=${STATE_DIR}/service-signing-key.bin

DEADMAN_VAULT_PASSPHRASE_A=${PASS_A}
DEADMAN_VAULT_PASSPHRASE_B=${PASS_B}

DEADMAN_BOOTSTRAP_ADMIN_EMAIL=${ADMIN_EMAIL}

DEADMAN_BACKUP_KEEP_COUNT=${BACKUP_KEEP}

DEADMAN_PUBLIC_BASE_URL=http://${ONION_HOST}
EOF
    if [[ "$SMTP_ENABLED" == "1" ]]; then
      cat <<EOF

DEADMAN_SMTP_HOST=${SMTP_HOST}
DEADMAN_SMTP_PORT=${SMTP_PORT}
DEADMAN_SMTP_USERNAME=${SMTP_USER}
DEADMAN_SMTP_PASSWORD=${SMTP_PASS}
DEADMAN_SMTP_FROM=${SMTP_FROM}
EOF
    fi
  } > "$ENV_FILE"
  chown "$DEADMAN_USER:$DEADMAN_USER" "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  ok "Wrote $ENV_FILE."
}

install_systemd_unit() {
  step "Installing systemd unit"
  install -m 0644 "$REPO_ROOT/ops/systemd/deadman-control.service" "$SYSTEMD_UNIT_DST"
  systemctl daemon-reload
  systemctl enable deadman-control >/dev/null
  ok "Enabled deadman-control.service."
}

install_logrotate() {
  step "Installing logrotate config"
  install -m 0644 "$REPO_ROOT/ops/systemd/deadman.logrotate" "$LOGROTATE_FILE"
  ok "Wrote $LOGROTATE_FILE (daily, 14 days kept, compressed, copytruncate)."
}

start_service_and_capture_share3() {
  step "Starting deadman-control and capturing recovery share"
  : > "$LOG_DIR/server.log"
  chown "$DEADMAN_USER:$DEADMAN_USER" "$LOG_DIR/server.log"
  systemctl restart deadman-control
  info "Tailing $LOG_DIR/server.log for the offline recovery share..."

  local tries=0
  local share3=""
  while (( tries < 60 )); do
    if grep -q "DEADMAN THRESHOLD VAULT CREATED" "$LOG_DIR/server.log" 2>/dev/null; then
      # Share 3 is the single hyphen-grouped hex token printed inside the
      # banner. Match the first single-field line that contains an
      # alphanumeric and is NOT a rule of only dashes/equals — the previous
      # matcher grabbed the "----" separator line (dashes are alphanumerics'
      # neighbours in its character class), handing the operator a row of
      # dashes instead of their recovery share.
      share3="$(awk '/DEADMAN THRESHOLD VAULT CREATED/{flag=1; next} /^==========/{flag=0} flag && NF==1 && $1 ~ /[A-Za-z0-9]/ && $1 !~ /^[-=]+$/ {print $1; exit}' "$LOG_DIR/server.log" | tr -d '[:space:]')"
      if [[ -n "$share3" ]]; then break; fi
    fi
    if grep -q "vault unlocked via env passphrases" "$LOG_DIR/server.log" 2>/dev/null \
       && [[ -s "$STATE_DIR/release-vault.json" ]]; then
      # Existing vault — no share 3 to capture this run.
      share3="(existing vault — share 3 not regenerated)"
      break
    fi
    tries=$((tries+1))
    sleep 1
  done

  if [[ -z "$share3" ]]; then
    warn "Could not extract share 3 automatically. Inspect $LOG_DIR/server.log manually."
  else
    OFFLINE_SHARE3="$share3"
    ok "Captured."
  fi
}

# verify_service_healthy confirms the service actually came up and is
# answering, instead of reporting success on a crash-looping unit. A bad
# config, an unreachable database, or a failed migration all surface here.
verify_service_healthy() {
  step "Verifying the service is healthy"
  local tries=0
  while (( tries < 30 )); do
    if systemctl is-active --quiet deadman-control \
       && curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${LISTEN_PORT}/ui/" 2>/dev/null; then
      ok "deadman-control is active and answering on 127.0.0.1:${LISTEN_PORT}."
      return
    fi
    tries=$((tries+1))
    sleep 1
  done
  warn "deadman-control did not become healthy within 30s."
  echo
  echo "  Last 40 lines of ${LOG_DIR}/server.log:"
  tail -n 40 "$LOG_DIR/server.log" 2>/dev/null || true
  echo
  echo "  systemctl status:"
  systemctl --no-pager status deadman-control 2>&1 | head -n 20 || true
  fail "Service failed its health check (see above). Common causes: database not reachable, a bad value in ${ENV_FILE}, or a migration that did not apply. Fix and re-run, or inspect 'journalctl -u deadman-control'."
}

# -------------------------------------------------------------------------
# Final report.
# -------------------------------------------------------------------------

print_final_report() {
  cat <<EOF

${C_BLD}${C_GRN}=============================================================${C_RST}
${C_BLD}  Deadman is installed and running.${C_RST}
${C_BLD}${C_GRN}=============================================================${C_RST}

  Onion address:    ${C_BLD}http://${ONION_HOST}${C_RST}
  Bootstrap admin:  ${ADMIN_EMAIL}
  Service:          systemctl status deadman-control
  Server log:       ${LOG_DIR}/server.log
  Env file:         ${ENV_FILE} (mode 0600)
  State dir:        ${STATE_DIR}

EOF

  if [[ -n "${OFFLINE_SHARE3:-}" ]]; then
    cat <<EOF
  ${C_BLD}${C_YEL}OFFLINE RECOVERY SHARE (share 3) — recorded ONCE${C_RST}

      ${C_BLD}${OFFLINE_SHARE3}${C_RST}

  Write this on paper. Store in a safe you control. With this share + ONE
  passphrase, you can recover the release key if the other passphrase is
  lost. The server will NOT print this again. A fingerprint is stored in
  the vault file for verification at recovery time.

EOF
  fi

  cat <<EOF
  ${C_BLD}What to do tomorrow morning${C_RST}

  1. Open ${C_BLD}http://${ONION_HOST}${C_RST} in Tor Browser.
  2. Register an account with the email ${ADMIN_EMAIL}. On a plain-HTTP
     onion the auth path is ${C_BLD}passphrase + TOTP${C_RST} (not a passkey —
     Tor Browser disables WebAuthn on onion origins). Choose a 12+ char
     passphrase, then add the shown setup key to an authenticator app
     (Aegis, Raivo, KeePassXC, 1Password, etc.) and confirm a code.
  3. ${C_BLD}Save the ten recovery codes${C_RST} shown once during setup — they are
     the only way back in if you lose your authenticator.
  4. Registration auto-promotes ${ADMIN_EMAIL} to admin (it matches the
     bootstrap email), so the top nav shows an ${C_BLD}Admin${C_RST} link straight
     away. Visit ${C_BLD}/ui/admin/${C_RST} for the operator panel.
  5. After that first registration, edit ${C_BLD}${ENV_FILE}${C_RST} and
     blank out ${C_BLD}DEADMAN_BOOTSTRAP_ADMIN_EMAIL${C_RST}, then
     ${C_BLD}systemctl restart deadman-control${C_RST}. Bootstrap is
     idempotent (won't re-promote once an admin exists) but leaving the
     value lying around is unnecessary attack surface.
  6. Read ${C_BLD}docs/self-hosting.md${C_RST} sections "Day 2 hardening" and
     "Hardening: interactive vault unlock" before letting anyone real
     depend on this instance.
  7. ${C_BLD}Install the watchdog${C_RST} on a SEPARATE host:
     ${C_BLD}sudo ./scripts/setup-watchdog.sh${C_RST} (run from the repo on
     that other host). Without it, a stuck scheduler is silent.
  8. Read ${C_BLD}docs/operator-risks.md${C_RST} if you intend to invite
     anyone outside your household to use this instance.

  ${C_BLD}If anything is wrong:${C_RST}

    journalctl -u deadman-control -n 200
    journalctl -u tor             -n 50
    cat ${LOG_DIR}/server.log

EOF

  if [[ "${DOCKER_GROUP_ADDED:-0}" == "1" ]] && [[ -n "${SUDO_USER:-}" ]]; then
    cat <<EOF
  ${C_BLD}Note:${C_RST} '${SUDO_USER}' was added to the docker group. Log out and
  back in (or run ${C_BLD}newgrp docker${C_RST}) to use docker without sudo.

EOF
  fi
}

# -------------------------------------------------------------------------
# Main.
# -------------------------------------------------------------------------

main() {
  if [[ "${1:-}" == "--non-interactive" ]]; then
    NON_INTERACTIVE=1
  fi

  cat <<EOF

${C_BLD}Deadman one-shot installer${C_RST}

  Repo: $REPO_ROOT

  This script will, in order:
    - Install Docker, Tor, Go 1.25, and small utilities (apt + go.dev)
    - Configure the host firewall (allow SSH, deny everything else)
    - Verify the system clock is NTP-synced
    - Prompt for an admin email and two vault passphrases
    - Generate random Postgres + MinIO secrets and persist them
    - Build the control-plane binary from this repo
    - Start Postgres + MinIO via docker compose, apply migrations
    - Configure Tor v3 hidden service and read back the .onion address
    - Write /etc/deadman/deadman.env (mode 0600, owned by deadman)
    - Install + start the deadman-control systemd service

  Total time: 2-5 minutes on a fresh VM (Argon2id key derivation is slow).
  You can ${C_BLD}^C${C_RST} at any prompt to abort cleanly.

EOF

  check_os
  check_prereqs
  check_time_sync
  prompt_settings
  create_user_and_dirs
  load_or_make_compose_env
  build_binary
  bring_up_stack
  run_migrations
  install_torrc
  write_env_file
  install_systemd_unit
  install_logrotate
  configure_firewall
  start_service_and_capture_share3
  verify_service_healthy
  print_final_report
}

main "$@"
