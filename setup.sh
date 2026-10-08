#!/usr/bin/env bash

set -Eeuo pipefail

VERSION="2.0.2"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_NAME="uis"
LOCKFILE="/run/uis.lock"
LOG_FILE="/var/log/uis-$(date +%F_%H%M%S).log"
TMP_DIR=""
SSH_HARDENING_FILE="/etc/ssh/sshd_config.d/99-uis-hardening.conf"
SYSCTL_FILE="/etc/sysctl.d/99-uis-hardening.conf"
FAIL2BAN_FILE="/etc/fail2ban/jail.d/uis-sshd.conf"
UFW_DEFAULTS_FILE="/etc/default/ufw"
UFW_BEFORE_FILE="/etc/ufw/before.rules"
SYSCTL_SERVICE="uis-sysctl.service"
SYSCTL_HELPER="/usr/local/sbin/uis-apply-sysctl"

APT_OPTS=(
  -o DPkg::Lock::Timeout=60
  -o Dpkg::Options::=--force-confdef
  -o Dpkg::Options::=--force-confold
)

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step() { echo -e "\n${BLUE}=== $* ===${NC}"; }

on_error() {
  local rc=$?
  local line=${1:-unknown}
  log_err "Ошибка на строке ${line} (exit ${rc})."
  log_err "Лог: ${LOG_FILE}"
  exit "$rc"
}
trap 'on_error $LINENO' ERR

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf -- "${TMP_DIR}"
  fi
}
trap cleanup EXIT

usage() {
  cat <<USAGE
UIS ${VERSION}

Использование:
  sudo bash setup.sh           # интерактивная установка
  sudo bash setup.sh --audit   # только проверка, ничего не меняет
  bash setup.sh --help
USAGE
}

say_ok()   { printf '  [%bOK%b] %s\n' "$GREEN" "$NC" "$*"; }
say_warn() { printf '  [%bWARN%b] %s\n' "$YELLOW" "$NC" "$*"; }
say_fail() { printf '  [%bFAIL%b] %s\n' "$RED" "$NC" "$*"; }

run_silent() {
  local desc="$1"; shift
  local log_file
  log_file=$(mktemp)
  echo -n -e "${GREEN}[INFO]${NC} ${desc}..."

  if "$@" >"$log_file" 2>&1; then
    echo -e " ${GREEN}[OK]${NC}"
    rm -f -- "$log_file"
  else
    local rc=$?
    echo -e " ${RED}[FAIL]${NC}"
    sed 's/^/  /' "$log_file" >&2 || true
    rm -f -- "$log_file"
    return "$rc"
  fi
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_err "Для установки нужен root. Для аудита используйте sudo bash setup.sh --audit."
    exit 1
  fi
}

setup_runtime() {
  mkdir -p /var/log
  TMP_DIR=$(mktemp -d /tmp/uis.XXXXXX)
  exec > >(tee -a "$LOG_FILE") 2>&1
  exec 200>"$LOCKFILE"
  flock -n 200 || { log_err "UIS уже запущен."; exit 1; }
}

backup_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local backup="${file}.bak.$(date +%F_%H%M%S)"
  cp -a -- "$file" "$backup"
  log_info "Backup: $backup"
}

write_atomic() {
  local target="$1"
  local mode="$2"
  shift 2
  local tmp="$TMP_DIR/$(basename "$target").tmp"
  cat >"$tmp"
  install -m "$mode" -o root -g root "$tmp" "$target"
}

unit_exists() { systemctl cat "$1" &>/dev/null; }

normalize_os_version() {
  local major=${OS_VERSION%%.*}
  local rest=${OS_VERSION#*.}
  local minor=${rest%%.*}
  [[ "$rest" == "$OS_VERSION" ]] && minor=0
  printf '%02d%02d' "$major" "$minor"
}

check_supported_os() {
  if [[ ! -r /etc/os-release ]]; then
    log_err "Не найден /etc/os-release."
    exit 1
  fi
  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VERSION="${VERSION_ID:-0}"
  OS_NAME="${PRETTY_NAME:-unknown}"

  log_info "ОС: $OS_NAME"

  case "$OS_ID" in
    ubuntu)
      local v
      v=$(normalize_os_version)
      if (( v < 2204 )); then
        log_err "UIS ${VERSION} не предназначен для Ubuntu < 22.04."
        log_err "Для нового сервера используйте Ubuntu 24.04 LTS."
        exit 1
      fi
      ;;
    debian)
      local major="${OS_VERSION%%.*}"
      if [[ ! "$major" =~ ^[0-9]+$ ]] || (( major < 12 )); then
        log_err "UIS ${VERSION} не предназначен для Debian < 12."
        exit 1
      fi
      ;;
    *)
      log_err "Неподдерживаемая ОС: $OS_NAME"
      exit 1
      ;;
  esac
}

install_base_packages() {
  log_step "1. Обновление системы"
  export DEBIAN_FRONTEND=noninteractive
  run_silent "apt update" apt-get "${APT_OPTS[@]}" update
  run_silent "full-upgrade" apt-get "${APT_OPTS[@]}" full-upgrade -y
  run_silent "autoremove" apt-get "${APT_OPTS[@]}" autoremove -y
  unset DEBIAN_FRONTEND

  log_step "2. Базовые пакеты"
  export DEBIAN_FRONTEND=noninteractive
  run_silent "Установка базовых пакетов" apt-get "${APT_OPTS[@]}" install -y \
    sudo openssh-server ufw fail2ban unattended-upgrades \
    htop iotop ncdu tmux curl wget net-tools ca-certificates
  unset DEBIAN_FRONTEND
}

configure_unattended_upgrades() {
  log_step "3. Автоматические обновления"
  write_atomic /etc/apt/apt.conf.d/20auto-upgrades 644 <<'EOF2'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF2
  log_info "Unattended upgrades включены ежедневно."
}

create_or_select_user() {
  log_step "4. Пользователь sudo"
  local user=""
  while :; do
    read -r -p "Имя пользователя [nrpems]: " user
    user=${user:-nrpems}
    if [[ ! "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
      log_warn "Некорректное имя пользователя."
      continue
    fi
    [[ "$user" == root ]] && { log_warn "root использовать нельзя."; continue; }
    break
  done

  if id "$user" &>/dev/null; then
    log_info "Пользователь $user уже существует."
  else
    log_warn "Введите пароль для $user."
    adduser --gecos "" "$user"
  fi
  usermod -aG sudo "$user"
  TARGET_USER="$user"
  log_info "$TARGET_USER состоит в sudo."
}

get_current_ssh_port() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}') || true
  if [[ "$p" =~ ^[0-9]+$ ]]; then
    printf '%s' "$p"
  else
    printf '22'
  fi
}

choose_ssh_port() {
  log_step "5. SSH порт"
  local current_port
  current_port=$(get_current_ssh_port)
  log_info "Текущий SSH порт: $current_port"

  while :; do
    read -r -p "Новый SSH порт [1234]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-1234}
    if [[ ! "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1024 || SSH_PORT > 65535 )); then
      log_warn "Используйте порт 1024-65535."
      continue
    fi
    if ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ":${SSH_PORT}$|\.${SSH_PORT}$"; then
      if [[ "$SSH_PORT" != "$current_port" ]]; then
        log_warn "Порт $SSH_PORT уже занят."
        continue
      fi
    fi
    break
  done
  log_info "Новый SSH порт: $SSH_PORT"
}

show_plan() {
  echo
  echo "============================================================"
  log_info "ПРЕДВАРИТЕЛЬНАЯ СВОДКА"
  echo "------------------------------------------------------------"
  printf 'ОС:             %s\n' "$OS_NAME"
  printf 'Пользователь:   %s\n' "$TARGET_USER"
  printf 'SSH порт:       %s\n' "$SSH_PORT"
  printf 'SSH auth:       пароль + public key\n'
  printf 'IPv6:            %s\n' "$([[ "$DISABLE_IPV6" =~ ^[Yy]$ ]] && echo 'отключить' || echo 'оставить')"
  printf 'Swap:            %s\n' "$([[ "$CREATE_SWAP" =~ ^[Yy]$ ]] && echo '2G при отсутствии' || echo 'не создавать')"
  printf 'BBR:             %s\n' "$([[ "$ENABLE_BBR" =~ ^[Yy]$ ]] && echo 'включить' || echo 'не менять')"
  printf 'Docker:          %s\n' "$([[ "$INSTALL_DOCKER" =~ ^[Yy]$ ]] && echo 'установить' || echo 'не устанавливать')"
  printf 'Chrony:          %s\n' "$([[ "$INSTALL_CHRONY" =~ ^[Yy]$ ]] && echo 'установить' || echo 'не устанавливать')"
  echo "------------------------------------------------------------"
  echo "Будет настроено: UFW, SSH hardening, Fail2Ban, ICMP DROP"
  echo "и проверяемый sysctl. Root будет заблокирован только после"
  echo "проверки второй SSH-сессии."
  echo "============================================================"
}

ask_options() {
  read -r -p "Отключить IPv6? (y/n, default y): " DISABLE_IPV6
  DISABLE_IPV6=${DISABLE_IPV6:-y}
  read -r -p "Создать Swap 2G, если его нет? (y/n, default y): " CREATE_SWAP
  CREATE_SWAP=${CREATE_SWAP:-y}
  read -r -p "Включить TCP BBR? (y/n, default y): " ENABLE_BBR
  ENABLE_BBR=${ENABLE_BBR:-y}
  read -r -p "Установить Docker? (y/n, default n): " INSTALL_DOCKER
  INSTALL_DOCKER=${INSTALL_DOCKER:-n}
  read -r -p "Установить Chrony? (y/n, default y): " INSTALL_CHRONY
  INSTALL_CHRONY=${INSTALL_CHRONY:-y}
  read -r -p "Изменить hostname? (ENTER = оставить): " NEW_HOSTNAME
  read -r -p "Изменить timezone? (например Europe/Moscow, ENTER = оставить): " NEW_TIMEZONE
}

configure_ufw() {
  log_step "6. UFW"
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null

  if ! ufw status 2>/dev/null | grep -Eq "${SSH_PORT}/tcp[[:space:]]+LIMIT"; then
    ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw delete "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    ufw limit "${SSH_PORT}/tcp" >/dev/null
  fi

  if [[ "$(ufw status | head -n1)" == "Status: inactive" ]]; then
    echo 'y' | ufw enable >/dev/null
  fi

  log_info "UFW активен: deny incoming / allow outgoing / rate-limit SSH."
}

configure_ssh() {
  log_step "7. SSH hardening"
  mkdir -p /etc/ssh/sshd_config.d
  backup_file "$SSH_HARDENING_FILE"

  if [[ -f /etc/systemd/system/ssh.socket.d/override.conf ]] && grep -q 'ListenStream=0.0.0.0:' /etc/systemd/system/ssh.socket.d/override.conf 2>/dev/null; then
    backup_file /etc/systemd/system/ssh.socket.d/override.conf
    rm -f /etc/systemd/system/ssh.socket.d/override.conf
    systemctl daemon-reload
  fi

  local ssh_address_family
  if [[ "$DISABLE_IPV6" =~ ^[Yy]$ ]]; then
    ssh_address_family="inet"
  else
    ssh_address_family="any"
  fi

  write_atomic "$SSH_HARDENING_FILE" 644 <<EOF2
# Managed by UIS ${VERSION}
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
AllowUsers ${TARGET_USER}
AddressFamily ${ssh_address_family}
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
UseDNS no
EOF2

  install -d -m 0755 -o root -g root /run/sshd

  if ! sshd -t; then
    log_err "sshd -t провалился. Старый SSH-конфиг не должен быть потерян."
    exit 1
  fi

  if unit_exists ssh.socket; then
    systemctl daemon-reload
    if systemctl is-active --quiet ssh.socket; then
      systemctl restart ssh.socket
    else
      systemctl stop ssh.service >/dev/null 2>&1 || true
      systemctl enable --now ssh.socket >/dev/null
    fi
  else
    systemctl restart ssh.service
  fi

  local effective_port effective_user root_login
  effective_port=$(sshd -T | awk '$1=="port" {print $2; exit}')
  effective_user=$(sshd -T | awk '$1=="allowusers" {$1=""; sub(/^ /,""); print; exit}')
  root_login=$(sshd -T | awk '$1=="permitrootlogin" {print $2; exit}')

  [[ "$effective_port" == "$SSH_PORT" ]] || { log_err "sshd слушает не тот порт: $effective_port"; exit 1; }
  [[ "$effective_user" == "$TARGET_USER" ]] || { log_err "AllowUsers не совпадает: $effective_user"; exit 1; }
  [[ "$root_login" == "no" ]] || { log_err "PermitRootLogin не установлен в no."; exit 1; }

  log_info "SSH hardening применён и проверен."
}

configure_icmp() {
  log_step "8. ICMP"
  backup_file "$UFW_BEFORE_FILE"

  if grep -qE '^-A ufw-before-input -p icmp --icmp-type echo-request -j DROP$' "$UFW_BEFORE_FILE"; then
    log_info "ICMP echo-request уже блокируется."
    return
  fi

  if grep -qE '^-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT$' "$UFW_BEFORE_FILE"; then
    sed -i 's/^-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT$/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/' "$UFW_BEFORE_FILE"
  else
    sed -i '/^-A ufw-user-input /i -A ufw-before-input -p icmp --icmp-type echo-request -j DROP' "$UFW_BEFORE_FILE"
  fi
  ufw reload >/dev/null
  log_info "IPv4 ICMP echo-request: DROP."
}

configure_ipv6() {
  log_step "9. IPv6 hardening"
  backup_file "$UFW_DEFAULTS_FILE"

  if [[ "$DISABLE_IPV6" =~ ^[Yy]$ ]]; then
    if grep -q '^IPV6=' "$UFW_DEFAULTS_FILE"; then
      sed -i 's/^IPV6=.*/IPV6=no/' "$UFW_DEFAULTS_FILE"
    else
      printf '\nIPV6=no\n' >> "$UFW_DEFAULTS_FILE"
    fi
    ufw reload >/dev/null 2>&1 || true
    log_info "UFW IPv6 support disabled (IPV6=no)."
  else
    if grep -q '^IPV6=' "$UFW_DEFAULTS_FILE"; then
      sed -i 's/^IPV6=.*/IPV6=yes/' "$UFW_DEFAULTS_FILE"
    else
      printf '\nIPV6=yes\n' >> "$UFW_DEFAULTS_FILE"
    fi
  fi
}

write_sysctl_config() {
  log_step "10. Kernel / sysctl hardening"
  backup_file "$SYSCTL_FILE"

  if [[ "$DISABLE_IPV6" =~ ^[Yy]$ ]]; then
    IPV6_LINES=$(cat <<'EOF2'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF2
)
  else
    IPV6_LINES="# IPv6 left enabled"
  fi

  write_atomic "$SYSCTL_FILE" 644 <<EOF2
# Managed by UIS ${VERSION}
${IPV6_LINES}
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF2

  if [[ "$ENABLE_BBR" =~ ^[Yy]$ ]]; then
    cat >> "$SYSCTL_FILE" <<'EOF2'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF2
  fi

  sysctl --system >/dev/null 2>&1 || true

  install_sysctl_reapply_service
  log_info "Sysctl hardening применён; post-network verification service enabled."
}

install_sysctl_reapply_service() {
  log_info "Устанавливаю post-network reapply service для детерминированного runtime state."

  write_atomic "$SYSCTL_HELPER" 755 <<'EOF2'
#!/usr/bin/env bash
set -u

/usr/sbin/sysctl --load=/etc/sysctl.d/99-uis-hardening.conf >/dev/null 2>&1 || true

if grep -q '^IPV6=no$' /etc/default/ufw 2>/dev/null; then
  for file in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -w "$file" ]] || continue
    echo 1 > "$file"
  done
fi
EOF2

  cat > "/etc/systemd/system/${SYSCTL_SERVICE}" <<EOF2
[Unit]
Description=UIS kernel hardening re-apply after network initialization
Wants=network-online.target
After=network-online.target systemd-sysctl.service

[Service]
Type=oneshot
ExecStart=${SYSCTL_HELPER}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF2
  chmod 644 "/etc/systemd/system/${SYSCTL_SERVICE}"
  systemctl daemon-reload
  systemctl enable "$SYSCTL_SERVICE" >/dev/null
  systemctl start "$SYSCTL_SERVICE"
}

configure_fail2ban() {
  log_step "11. Fail2Ban"
  mkdir -p /etc/fail2ban/jail.d
  backup_file "$FAIL2BAN_FILE"

  write_atomic "$FAIL2BAN_FILE" 644 <<EOF2
[DEFAULT]
bantime = 24h
findtime = 10m
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
EOF2

  fail2ban-client -t >/dev/null
  systemctl enable --now fail2ban >/dev/null
  log_info "Fail2Ban: sshd / 3 attempts / 10m / 24h."
}

configure_swap() {
  [[ "$CREATE_SWAP" =~ ^[Yy]$ ]] || return 0
  log_step "12. Swap"

  if swapon --show | awk 'NR>1 {print $1}' | grep -q .; then
    log_info "Swap уже активен."
    return
  fi

  local free_mb
  free_mb=$(df -BM / | awk 'NR==2 {gsub("M","",$4); print $4}')
  if (( free_mb < 2560 )); then
    log_warn "Недостаточно свободного места для 2G swap: ${free_mb}M."
    return
  fi

  if ! fallocate -l 2G /swapfile 2>/dev/null; then
    dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  fi
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -qF '/swapfile none swap sw 0 0' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -w vm.swappiness=10 >/dev/null
  sysctl -w vm.vfs_cache_pressure=50 >/dev/null
  grep -qF 'vm.swappiness = 10' "$SYSCTL_FILE" || echo 'vm.swappiness = 10' >> "$SYSCTL_FILE"
  grep -qF 'vm.vfs_cache_pressure = 50' "$SYSCTL_FILE" || echo 'vm.vfs_cache_pressure = 50' >> "$SYSCTL_FILE"
  log_info "Swap 2G создан."
}

configure_bbr() {
  [[ "$ENABLE_BBR" =~ ^[Yy]$ ]] || return 0
  log_step "13. BBR"

  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | tr ' ' '\n' | grep -qx bbr; then
    modprobe tcp_bbr 2>/dev/null || true
  fi

  local available
  available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
  if ! grep -qw bbr <<<"$available"; then
    log_warn "BBR недоступен в этом kernel."
    return 0
  fi

  sysctl -w net.core.default_qdisc=fq >/dev/null
  sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
  grep -qF 'net.core.default_qdisc = fq' "$SYSCTL_FILE" || echo 'net.core.default_qdisc = fq' >> "$SYSCTL_FILE"
  grep -qF 'net.ipv4.tcp_congestion_control = bbr' "$SYSCTL_FILE" || echo 'net.ipv4.tcp_congestion_control = bbr' >> "$SYSCTL_FILE"
  log_info "BBR включён."
}

configure_chrony() {
  [[ "$INSTALL_CHRONY" =~ ^[Yy]$ ]] || return 0
  log_step "14. Chrony"
  export DEBIAN_FRONTEND=noninteractive
  run_silent "Установка Chrony" apt-get "${APT_OPTS[@]}" install -y chrony
  unset DEBIAN_FRONTEND
  systemctl enable --now chrony >/dev/null
  log_info "Chrony включён."
}

configure_docker() {
  [[ "$INSTALL_DOCKER" =~ ^[Yy]$ ]] || return 0
  log_step "15. Docker"
  if command -v docker >/dev/null 2>&1; then
    usermod -aG docker "$TARGET_USER"
    log_warn "Docker уже установлен. $TARGET_USER добавлен в группу docker."
    return
  fi

  curl -fsSL https://get.docker.com -o "$TMP_DIR/get-docker.sh"
  sh "$TMP_DIR/get-docker.sh"
  usermod -aG docker "$TARGET_USER"
  log_warn "Docker установлен. Публикация контейнерных портов может обходить UFW."
  log_warn "Для внешних сервисов явно настройте firewall/DOCKER-USER или bind на 127.0.0.1."
}

configure_host() {
  log_step "16. Hostname / timezone"
  if [[ -n "${NEW_HOSTNAME}" ]]; then
    if [[ "$NEW_HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]]; then
      hostnamectl set-hostname "$NEW_HOSTNAME"
      log_info "Hostname: $NEW_HOSTNAME"
    else
      log_warn "Hostname пропущен: некорректный формат."
    fi
  fi

  if [[ -n "${NEW_TIMEZONE}" ]]; then
    if timedatectl list-timezones | grep -Fxq "$NEW_TIMEZONE"; then
      timedatectl set-timezone "$NEW_TIMEZONE"
      log_info "Timezone: $NEW_TIMEZONE"
    else
      log_warn "Timezone '$NEW_TIMEZONE' не существует."
    fi
  fi
}

configure_optional_services() {
  log_step "17. Ненужные сервисы"

  for unit in snapd.service snapd.socket; do
    if unit_exists "$unit"; then
      systemctl disable --now "$unit" 2>/dev/null || true
    fi
  done

  for unit in cups.service; do
    if unit_exists "$unit"; then
      systemctl disable --now "$unit" 2>/dev/null || true
    fi
  done

  log_info "snapd/cups: отключены, где присутствуют."
}

validate_access_before_root_lock() {
  log_step "18. Проверка доступа"
  local listening
  listening=$(ss -H -lnt | awk '{print $4}' | grep -E "(:|\\.)${SSH_PORT}$" || true)
  if [[ -z "$listening" ]]; then
    log_err "Новый SSH порт $SSH_PORT не слушается. Root не будет блокироваться."
    exit 1
  fi

  if ! sshd -t; then
    log_err "sshd -t не проходит. Root не будет блокироваться."
    exit 1
  fi

  echo
  echo "============================================================"
  log_warn "НЕ ЗАКРЫВАЙТЕ ТЕКУЩУЮ СЕССИЮ."
  echo "Откройте вторую SSH-сессию и проверьте:"
  echo "  ssh -p ${SSH_PORT} ${TARGET_USER}@<IP>"
  echo "  sudo whoami     # должно вывести root"
  echo "============================================================"
  read -r -p "Вторая SSH-сессия успешно работает? (yes/no): " ACCESS_OK
  if [[ "$ACCESS_OK" != "yes" ]]; then
    log_warn "Root оставлен разблокированным. Сначала исправьте доступ."
    return 1
  fi
  return 0
}

lock_root() {
  log_step "19. Блокировка root account"
  local status
  status=$(passwd -S root 2>/dev/null | awk '{print $2}')
  if [[ "$status" == "L" ]]; then
    log_info "root уже locked."
  else
    passwd -l root >/dev/null
    log_info "root account locked."
  fi
}

cleanup_old_ssh_ufw_rule() {
  local old_port="$1"
  [[ -n "$old_port" && "$old_port" =~ ^[0-9]+$ ]] || return 0
  [[ "$old_port" == "$SSH_PORT" ]] && return 0

  if ufw status | grep -Eq "${old_port}/tcp.*ALLOW|${old_port}/tcp.*LIMIT"; then
    log_warn "Найден старый UFW SSH rule на $old_port. Он НЕ удаляется автоматически."
    log_warn "После дополнительной проверки можно удалить: sudo ufw delete limit ${old_port}/tcp"
  fi
}

create_logrotate() {
  cat > /etc/logrotate.d/uis <<'EOF2'
/var/log/uis-*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
}
EOF2
  chmod 644 /etc/logrotate.d/uis
}

post_setup_checks() {
  log_step "20. Финальная проверка"
  run_audit || true
}

check_line() {
  local label="$1" expected="$2" actual="$3" level="${4:-FAIL}"
  if [[ "$actual" == "$expected" ]]; then
    say_ok "$label"
    return 0
  fi
  if [[ "$level" == WARN ]]; then
    say_warn "$label (ожидалось: '$expected', фактически: '$actual')"
    return 0
  fi
  say_fail "$label (ожидалось: '$expected', фактически: '$actual')"
  return 1
}

run_audit() {
  local fail=0
  local warn=0
  local port root_locked
  port=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}' || true)

  echo
  echo "============================================================"
  echo "UIS ${VERSION} AUDIT"
  echo "============================================================"
  echo "Hostname: $(hostname)"
  echo "OS:       ${PRETTY_NAME:-unknown}"
  echo

  if sshd -t 2>/dev/null; then say_ok "sshd -t"; else say_fail "sshd -t"; fail=$((fail + 1)); fi
  if [[ "$port" =~ ^[0-9]+$ ]] && ss -H -lnt | awk '{print $4}' | grep -Eq "(:|\\.)${port}$"; then
    say_ok "SSH listening on ${port}"
  else
    say_fail "SSH listening on configured port ${port:-unknown}"; fail=$((fail + 1))
  fi

  local permit_root password_auth allow_users address_family
  permit_root=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin" {print $2; exit}')
  password_auth=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication" {print $2; exit}')
  allow_users=$(sshd -T 2>/dev/null | awk '$1=="allowusers" {$1=""; sub(/^ /,""); print; exit}')
  address_family=$(sshd -T 2>/dev/null | awk '$1=="addressfamily" {print $2; exit}')
  check_line "PermitRootLogin" "no" "$permit_root" || fail=$((fail + 1))
  check_line "PasswordAuthentication" "yes" "$password_auth" || fail=$((fail + 1))
  if grep -q '^IPV6=no$' "$UFW_DEFAULTS_FILE" 2>/dev/null; then
    [[ "$address_family" == "inet" ]] && say_ok "SSH AddressFamily inet" || { say_fail "SSH AddressFamily expected inet, got $address_family"; fail=$((fail + 1)); }
  else
    [[ "$address_family" == "any" ]] && say_ok "SSH AddressFamily any" || { say_warn "SSH AddressFamily is $address_family while IPv6 is enabled"; warn=$((warn + 1)); }
  fi
  [[ -n "$allow_users" ]] && say_ok "AllowUsers = $allow_users" || { say_fail "AllowUsers"; fail=$((fail + 1)); }

  if id "${allow_users%% *}" &>/dev/null; then
    say_ok "SSH user exists: ${allow_users%% *}"
  else
    say_fail "SSH user does not exist: ${allow_users%% *}"; fail=$((fail + 1))
  fi

  root_locked=$(passwd -S root 2>/dev/null | awk '{print $2}')
  if [[ "$root_locked" == "L" ]]; then say_ok "root password locked"; else say_warn "root password is not locked"; warn=$((warn + 1)); fi

  if sudo -l -U "${allow_users%% *}" 2>/dev/null | grep -Fq '(ALL : ALL) ALL'; then
    say_ok "sudo access for ${allow_users%% *}"
  else
    say_fail "sudo access for ${allow_users%% *}"; fail=$((fail + 1))
  fi

  local ufw_status
  ufw_status=$(ufw status 2>/dev/null | head -n1 || true)
  check_line "UFW active" "Status: active" "$ufw_status" || fail=$((fail + 1))
  if grep -Fq "$port/tcp" <(ufw status 2>/dev/null) && grep -Fq "LIMIT" <(ufw status 2>/dev/null); then
    say_ok "UFW rate-limit for SSH $port/tcp"
  else
    say_fail "UFW rate-limit for SSH $port/tcp"; fail=$((fail + 1));
  fi

  if grep -qE '^-A ufw-before-input -p icmp --icmp-type echo-request -j DROP$' "$UFW_BEFORE_FILE" 2>/dev/null; then
    say_ok "IPv4 ping blocked in UFW"
  else
    say_fail "IPv4 ping blocked in UFW"; fail=$((fail + 1));
  fi

  if systemctl is-enabled fail2ban &>/dev/null && systemctl is-active --quiet fail2ban; then
    say_ok "Fail2Ban enabled + active"
  else
    say_fail "Fail2Ban enabled + active"; fail=$((fail + 1));
  fi

  local f2b_cfg
  f2b_cfg=$(cat "$FAIL2BAN_FILE" 2>/dev/null || true)
  if grep -qF 'maxretry = 3' <<<"$f2b_cfg" && grep -qF 'findtime = 10m' <<<"$f2b_cfg" && grep -qF 'bantime = 24h' <<<"$f2b_cfg" && grep -qF "port = $port" <<<"$f2b_cfg"; then
    say_ok "Fail2Ban SSH policy"
  else
    say_fail "Fail2Ban SSH policy"; fail=$((fail + 1));
  fi

  local v k expected actual
  declare -a SYSCTL_CHECKS=(
    'net.ipv4.conf.all.rp_filter=1'
    'net.ipv4.conf.default.rp_filter=1'
    'net.ipv4.conf.all.accept_source_route=0'
    'net.ipv4.conf.default.accept_source_route=0'
    'net.ipv4.conf.all.accept_redirects=0'
    'net.ipv4.conf.default.accept_redirects=0'
    'net.ipv4.conf.all.secure_redirects=0'
    'net.ipv4.conf.default.secure_redirects=0'
    'net.ipv4.conf.all.send_redirects=0'
    'net.ipv4.conf.default.send_redirects=0'
    'net.ipv4.icmp_ignore_bogus_error_responses=1'
    'net.ipv4.icmp_echo_ignore_broadcasts=1'
    'net.ipv4.conf.all.log_martians=1'
    'net.ipv4.conf.default.log_martians=1'
    'kernel.dmesg_restrict=1'
    'kernel.kptr_restrict=2'
    'kernel.yama.ptrace_scope=1'
    'fs.protected_hardlinks=1'
    'fs.protected_symlinks=1'
    'fs.suid_dumpable=0'
    'vm.swappiness=10'
    'vm.vfs_cache_pressure=50'
  )
  for v in "${SYSCTL_CHECKS[@]}"; do
    k=${v%%=*}; expected=${v#*=}; actual=$(sysctl -n "$k" 2>/dev/null || echo MISSING)
    if [[ "$actual" == "$expected" ]]; then say_ok "$k=$expected"; else say_fail "$k expected $expected, got $actual"; fail=$((fail + 1)); fi
  done

  if grep -qF 'net.core.default_qdisc = fq' "$SYSCTL_FILE" 2>/dev/null; then
    actual=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo MISSING)
    [[ "$actual" == fq ]] && say_ok "BBR qdisc fq" || { say_fail "BBR qdisc fq (got $actual)"; fail=$((fail + 1)); }
  fi
  if grep -qF 'net.ipv4.tcp_congestion_control = bbr' "$SYSCTL_FILE" 2>/dev/null; then
    actual=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo MISSING)
    [[ "$actual" == bbr ]] && say_ok "TCP congestion control bbr" || { say_fail "TCP congestion control bbr (got $actual)"; fail=$((fail + 1)); }
  fi

  if grep -q '^IPV6=no$' "$UFW_DEFAULTS_FILE" 2>/dev/null; then
    local ipv6_all ipv6_default ipv6_bad
    ipv6_all=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo MISSING)
    ipv6_default=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo MISSING)
    ipv6_bad=0
    while read -r key value; do
      [[ "$key" == net.ipv6.conf.*.disable_ipv6 ]] || continue
      [[ "$value" == 1 ]] || ipv6_bad=1
    done < <(sysctl -a 2>/dev/null | grep '^net.ipv6.conf\..*\.disable_ipv6 = ' || true)
    if [[ "$ipv6_all" == 1 && "$ipv6_default" == 1 && "$ipv6_bad" == 0 ]] && ! ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
      say_ok "IPv6 disabled at sysctl + UFW"
    else
      say_fail "IPv6 disable requested but runtime/interface state is not fully disabled"; fail=$((fail + 1));
    fi
  fi

  if swapon --show 2>/dev/null | awk 'NR>1 {print}' | grep -q .; then say_ok "Swap active"; else say_warn "Swap inactive"; warn=$((warn + 1)); fi

  if dpkg-query -W -f='${Status}\n' unattended-upgrades 2>/dev/null | grep -q 'install ok installed'; then say_ok "unattended-upgrades installed"; else say_fail "unattended-upgrades installed"; fail=$((fail + 1)); fi

  local pending
  pending=$(apt-get -s upgrade 2>/dev/null | awk '/^[0-9]+ upgraded/ {print $1; exit}')
  [[ "${pending:-0}" == 0 ]] && say_ok "No pending apt upgrades" || { say_warn "Pending apt upgrades: ${pending:-unknown}"; warn=$((warn + 1)); }

  if [[ -n "${INSTALL_CHRONY:-}" && "${INSTALL_CHRONY}" =~ ^[Yy]$ ]] || systemctl cat chrony.service &>/dev/null; then
    if systemctl is-active --quiet chrony; then say_ok "Chrony active"; else say_warn "Chrony installed but inactive"; warn=$((warn + 1)); fi
  fi

  if systemctl list-units --state=failed --no-legend | grep -q .; then
    say_fail "Failed systemd units present"; fail=$((fail + 1));
  else
    say_ok "No failed systemd units"
  fi

  if systemctl is-active --quiet snapd 2>/dev/null; then say_warn "snapd is active"; warn=$((warn + 1)); else say_ok "snapd not active"; fi

  echo
  echo "============================================================"
  if (( fail == 0 )); then
    echo -e "${GREEN}AUDIT PASS${NC} — failures: 0, warnings: ${warn}"
    return 0
  else
    echo -e "${RED}AUDIT FAIL${NC} — failures: ${fail}, warnings: ${warn}"
    return 1
  fi
}

main_setup() {
  require_root
  setup_runtime
  check_supported_os
  install_base_packages
  configure_unattended_upgrades
  create_or_select_user
  choose_ssh_port
  ask_options
  show_plan

  local confirm
  read -r -p "Продолжить? (y/n, default y): " confirm
  confirm=${confirm:-y}
  [[ "$confirm" =~ ^[Yy]$ ]] || { log_warn "Отменено."; exit 0; }

  local old_ssh_port
  old_ssh_port=$(get_current_ssh_port)

  configure_ufw
  configure_ssh
  configure_icmp
  configure_ipv6
  write_sysctl_config
  configure_fail2ban
  configure_swap
  configure_bbr
  configure_chrony
  configure_docker
  configure_host
  configure_optional_services
  create_logrotate

  cleanup_old_ssh_ufw_rule "$old_ssh_port"

  if ! validate_access_before_root_lock; then
    echo
    log_warn "Настройка завершена, но root account оставлен разблокированным."
    log_info "После проверки доступа запустите: sudo bash setup.sh --audit"
    exit 0
  fi

  lock_root
  post_setup_checks

  echo
  echo "============================================================"
  log_info "UIS ${VERSION} ЗАВЕРШЁН"
  echo "User: ${TARGET_USER}"
  echo "Port: ${SSH_PORT}"
  echo "Log:  ${LOG_FILE}"
  echo "============================================================"
  log_warn "Рекомендуется один раз выполнить reboot и затем повторить audit:"
  echo "  sudo reboot"
  echo "  sudo bash setup.sh --audit"
}

main_audit() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log_err "Audit должен запускаться от root: sudo bash setup.sh --audit"
    exit 1
  fi
  setup_runtime
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
  fi
  trap - ERR
  run_audit
  local rc=$?
  exit "$rc"
}

case "${1:-}" in
  --audit|-a)
    main_audit
    ;;
  --help|-h)
    usage
    ;;
  --version|-v)
    echo "$VERSION"
    ;;
  "")
    main_setup
    ;;
  *)
    usage
    exit 2
    ;;
esac
