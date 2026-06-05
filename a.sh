#!/usr/bin/env bash

set -u
set -o pipefail 2>/dev/null || true
IFS='
	 '
umask 077

VERSION="1.0.0"
COLOR=1
QUIET=0
JSON=0
MARKDOWN=0
ACTIVE=0
FULL=1
FAST=0
OUTFILE=""

TMPDIR="${TMPDIR:-/tmp}"

FINDING_COUNT=0
COUNTS_CRITICAL=0
COUNTS_HIGH=0
COUNTS_MEDIUM=0
COUNTS_LOW=0
COUNTS_INFO=0
FINDINGS_TEXT=""
FINDINGS_JSON=""
FINDINGS_MD=""
TOP_FINDINGS_TEXT=""
TOP_FINDINGS_MD=""
SUMMARY_TEXT=""
START_TS="$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	COLOR=1
else
	COLOR=0
fi

usage() {
	cat <<'EOF'
linbean.sh - read-only Linux privilege-escalation risk auditor

Usage:
  ./linbean.sh [options]

Options:
  --help           Show this help text
  --no-color       Disable ANSI colors
  --quiet          Suppress informational findings in text output
  --json           Emit valid JSON instead of text
  --markdown       Emit Markdown instead of text
  --active         Run controlled write/execute validation probes
  --output <file>  Write the report to a file; path must be under /tmp
  --full           Run broader filesystem checks (default)
  --fast           Skip slower filesystem checks

Safety:
  Default mode is read-only except for optional report output under /tmp.
  --active creates and removes harmless marker files to validate exposure.
  It does not exploit vulnerabilities, dump secrets, brute force, persist, or
  transmit data.
EOF
}

die() {
	printf '%s\n' "Error: $*" >&2
	exit 1
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--help) usage; exit 0 ;;
			--no-color) COLOR=0 ;;
			--quiet) QUIET=1 ;;
			--json) JSON=1; MARKDOWN=0; COLOR=0 ;;
			--markdown) MARKDOWN=1; JSON=0; COLOR=0 ;;
			--active) ACTIVE=1 ;;
			--full) FULL=1; FAST=0 ;;
			--fast) FAST=1; FULL=0 ;;
			--output)
				shift
				[ "$#" -gt 0 ] || die "--output requires a file path"
				OUTFILE="$1"
				;;
			*) die "unknown option: $1" ;;
		esac
		shift
	done

	if [ -n "$OUTFILE" ]; then
		case "$OUTFILE" in
			/tmp/*) : ;;
			*) die "--output must be under /tmp to preserve read-only behavior elsewhere" ;;
		esac
	fi
}

color() {
	[ "$COLOR" -eq 1 ] || return 0
	case "$1" in
		red) printf '\033[31m' ;;
		green) printf '\033[32m' ;;
		yellow) printf '\033[33m' ;;
		blue) printf '\033[34m' ;;
		magenta) printf '\033[35m' ;;
		cyan) printf '\033[36m' ;;
		bold) printf '\033[1m' ;;
		reset) printf '\033[0m' ;;
	esac
}

has_cmd() {
	command -v "$1" >/dev/null 2>&1
}

safe_read() {
	[ -r "$1" ] || return 1
	sed -n '1,80p' "$1" 2>/dev/null
}

one_line() {
	printf '%s' "$*" | tr '\n\r\t' '   ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
}

json_escape() {
	printf '%s' "$*" | awk '
	BEGIN { ORS="" }
	{
		gsub(/\\/,"\\\\")
		gsub(/"/,"\\\"")
		gsub(/\t/,"\\t")
		gsub(/\r/,"\\r")
		gsub(/\n/,"\\n")
		print
		if (NR != 0) print "\\n"
	}' | sed 's/\\n$//'
}

md_escape_table() {
	printf '%s' "$*" | tr '\n\r\t' '   ' | sed 's/\\/\\\\/g; s/|/\\|/g; s/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
}

md_bullets() {
	text="$1"
	printf '%s\n' "$text" | awk '
	BEGIN { RS = ";"; ORS = "" }
	{
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
		if ($0 != "") print $0 "\n"
	}' | while IFS= read -r item; do
		[ -n "$item" ] || continue
		printf -- '- %s\n' "$item"
	done
}

severity_rank() {
	case "$1" in
		Critical) printf 5 ;;
		High) printf 4 ;;
		Medium) printf 3 ;;
		Low) printf 2 ;;
		Info) printf 1 ;;
		*) printf 0 ;;
	esac
}

severity_color() {
	case "$1" in
		Critical|High) color red ;;
		Medium) color yellow ;;
		Low) color cyan ;;
		Info) color green ;;
	esac
}

term_width() {
	width=100
	if has_cmd tput; then
		width="$(tput cols 2>/dev/null || printf 100)"
	fi
	case "$width" in
		''|*[!0-9]*) width=100 ;;
	esac
	[ "$width" -lt 78 ] && width=78
	[ "$width" -gt 120 ] && width=120
	printf '%s' "$width"
}

rule() {
	char="${1:--}"
	width="$(term_width)"
	awk -v c="$char" -v w="$width" 'BEGIN { for (i = 0; i < w; i++) printf "%s", c; printf "\n" }'
}

wrap_text() {
	indent="$1"
	text="$2"
	width="$(term_width)"
	body_width=$((width - indent))
	[ "$body_width" -lt 40 ] && body_width=40
	pad="$(printf '%*s' "$indent" '')"
	printf '%s\n' "$text" | fold -s -w "$body_width" 2>/dev/null | sed "s/^/$pad/"
}

print_preserved() {
	indent="$1"
	text="$2"
	pad="$(printf '%*s' "$indent" '')"
	printf '%s\n' "$text" | sed "s/^/$pad/"
}

format_label() {
	label="$1"
	value="$2"
	printf '  %s%-13s%s ' "$(color bold)" "$label" "$(color reset)"
	wrap_text 17 "$value" | sed '1s/^                 //'
}

format_bullets() {
	text="$1"
	printf '%s\n' "$text" | awk '
	BEGIN { RS = ";"; ORS = "" }
	{
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
		if ($0 != "") print $0 "\n"
	}' | while IFS= read -r item; do
		[ -n "$item" ] || continue
		printf '    - '
		print_preserved 6 "$item" | sed '1s/^      //'
	done
}

severity_badge() {
	sev="$1"
	printf '%s[%s]%s' "$(severity_color "$sev")" "$sev" "$(color reset)"
}

format_finding_text() {
	id="$1"
	title="$2"
	severity="$3"
	confidence="$4"
	evidence="$5"
	why="$6"
	remediation="$7"
	commands="$8"

	printf '%s\n' "$(rule '-')"
	printf '%sFinding %03d%s  %s\n' "$(color bold)" "$id" "$(color reset)" "$title"
	printf '  Severity      %s\n' "$(severity_badge "$severity")"
	printf '  Confidence    %s\n\n' "$confidence"
	printf '  %sEvidence%s\n' "$(color bold)" "$(color reset)"
	format_bullets "$evidence"
	printf '\n'
	format_label "Impact" "$why"
	format_label "Fix" "$remediation"
	if [ -n "$commands" ]; then
		format_label "Commands" "$commands"
	fi
	printf '\n'
}

format_top_finding() {
	id="$1"
	title="$2"
	severity="$3"
	confidence="$4"
	evidence="$5"

	printf '  %s  #%03d  %s\n' "$(severity_badge "$severity")" "$id" "$title"
	printf '        Confidence: %s\n' "$confidence"
	printf '        Evidence: '
	print_preserved 18 "$(one_line "$evidence")" | sed '1s/^                  //'
	printf '\n'
}

format_finding_md() {
	id="$1"
	title="$2"
	severity="$3"
	confidence="$4"
	evidence="$5"
	why="$6"
	remediation="$7"
	commands="$8"

	printf '## Finding %03d: %s\n\n' "$id" "$title"
	printf '| Field | Value |\n'
	printf '|---|---|\n'
	printf '| Severity | %s |\n' "$(md_escape_table "$severity")"
	printf '| Confidence | %s |\n\n' "$(md_escape_table "$confidence")"
	printf '### Evidence\n\n'
	md_bullets "$evidence"
	printf '\n### Impact\n\n%s\n\n' "$why"
	printf '### Recommended Remediation\n\n%s\n\n' "$remediation"
	if [ -n "$commands" ]; then
		printf '### Commands Used\n\n`%s`\n\n' "$(printf '%s' "$commands" | sed 's/`/'\''/g')"
	fi
}

format_top_finding_md() {
	id="$1"
	title="$2"
	severity="$3"
	confidence="$4"
	evidence="$5"

	printf '| %03d | %s | %s | %s | %s |\n' \
		"$id" \
		"$(md_escape_table "$severity")" \
		"$(md_escape_table "$confidence")" \
		"$(md_escape_table "$title")" \
		"$(md_escape_table "$(one_line "$evidence")")"
}

increment_count() {
	case "$1" in
		Critical) COUNTS_CRITICAL=$((COUNTS_CRITICAL + 1)) ;;
		High) COUNTS_HIGH=$((COUNTS_HIGH + 1)) ;;
		Medium) COUNTS_MEDIUM=$((COUNTS_MEDIUM + 1)) ;;
		Low) COUNTS_LOW=$((COUNTS_LOW + 1)) ;;
		Info) COUNTS_INFO=$((COUNTS_INFO + 1)) ;;
	esac
}

add_finding() {
	title="$1"
	severity="$2"
	confidence="$3"
	evidence="$4"
	why="$5"
	remediation="$6"
	commands="${7:-}"

	[ "$QUIET" -eq 1 ] && [ "$severity" = "Info" ] && return 0

	FINDING_COUNT=$((FINDING_COUNT + 1))
	increment_count "$severity"

	text_block="$(format_finding_text "$FINDING_COUNT" "$title" "$severity" "$confidence" "$evidence" "$why" "$remediation" "$commands")"
	FINDINGS_TEXT="${FINDINGS_TEXT}${text_block}"$'\n'
	FINDINGS_TEXT="${FINDINGS_TEXT}"$'\n'
	if [ "$(severity_rank "$severity")" -ge 3 ]; then
		top_block="$(format_top_finding "$FINDING_COUNT" "$title" "$severity" "$confidence" "$evidence")"
		TOP_FINDINGS_TEXT="${TOP_FINDINGS_TEXT}${top_block}"$'\n\n'
		top_md_block="$(format_top_finding_md "$FINDING_COUNT" "$title" "$severity" "$confidence" "$evidence")"
		TOP_FINDINGS_MD="${TOP_FINDINGS_MD}${top_md_block}"$'\n'
	fi

	md_block="$(format_finding_md "$FINDING_COUNT" "$title" "$severity" "$confidence" "$evidence" "$why" "$remediation" "$commands")"
	FINDINGS_MD="${FINDINGS_MD}${md_block}"$'\n\n'

	json_obj="$(
		printf '{"id":%s,' "$FINDING_COUNT"
		printf '"title":"%s",' "$(json_escape "$title")"
		printf '"severity":"%s",' "$(json_escape "$severity")"
		printf '"severity_rank":%s,' "$(severity_rank "$severity")"
		printf '"confidence":"%s",' "$(json_escape "$confidence")"
		printf '"evidence":"%s",' "$(json_escape "$evidence")"
		printf '"why_it_matters":"%s",' "$(json_escape "$why")"
		printf '"recommended_remediation":"%s",' "$(json_escape "$remediation")"
		printf '"commands_used":"%s"}' "$(json_escape "$commands")"
	)"
	if [ -n "$FINDINGS_JSON" ]; then
		FINDINGS_JSON="${FINDINGS_JSON},${json_obj}"
	else
		FINDINGS_JSON="$json_obj"
	fi
}

is_writable_path() {
	path="$1"
	[ -e "$path" ] || return 1
	[ -w "$path" ] && return 0
	return 1
}

is_world_writable() {
	path="$1"
	[ -e "$path" ] || return 1
	[ -L "$path" ] && return 1
	if has_cmd stat; then
		mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null || true)"
		case "$mode" in
			???|????)
				last="${mode#${mode%?}}"
				[ $((last & 2)) -ne 0 ] && return 0
				;;
		esac
	fi
	[ -w "$path" ] && [ ! -O "$path" ] && return 0
	return 1
}

owner_of() {
	if has_cmd stat; then
		stat -c '%U:%G' "$1" 2>/dev/null || stat -f '%Su:%Sg' "$1" 2>/dev/null || printf 'unknown'
	else
		ls -ld "$1" 2>/dev/null | awk '{print $3 ":" $4}'
	fi
}

mode_of() {
	if has_cmd stat; then
		stat -c '%A %a' "$1" 2>/dev/null || stat -f '%Sp %Lp' "$1" 2>/dev/null || printf 'unknown'
	else
		ls -ld "$1" 2>/dev/null | awk '{print $1}'
	fi
}

active_marker_name() {
	printf '.linbean_probe_%s_%s' "$$" "$(date +%s 2>/dev/null || printf 0)"
}

active_write_probe_dir() {
	[ "$ACTIVE" -eq 1 ] || return 1
	dir="$1"
	[ -d "$dir" ] || return 1
	marker="$dir/$(active_marker_name)"
	if (umask 077; : > "$marker") 2>/dev/null; then
		rm -f "$marker" 2>/dev/null || true
		return 0
	fi
	rm -f "$marker" 2>/dev/null || true
	return 1
}

active_exec_probe_dir() {
	[ "$ACTIVE" -eq 1 ] || return 1
	dir="$1"
	[ -d "$dir" ] || return 1
	marker="$dir/$(active_marker_name).sh"
	if ({ printf '%s\n' '#!/bin/sh' 'exit 23' > "$marker"; } 2>/dev/null) && chmod 700 "$marker" 2>/dev/null; then
		"$marker" >/dev/null 2>&1
		rc="$?"
		rm -f "$marker" 2>/dev/null || true
		[ "$rc" -eq 23 ] && return 0
	fi
	rm -f "$marker" 2>/dev/null || true
	return 1
}

limit_lines() {
	cat
}

section() {
	:
}

collect_system_info() {
	os="unknown"
	[ -r /etc/os-release ] && os="$(awk -F= '/^PRETTY_NAME=/{gsub(/^"|"$/,"",$2); print $2}' /etc/os-release 2>/dev/null)"
	kernel="$(uname -r 2>/dev/null || printf unknown)"
	arch="$(uname -m 2>/dev/null || printf unknown)"
	host="$(hostname 2>/dev/null || uname -n 2>/dev/null || printf unknown)"
	up="$(uptime -p 2>/dev/null || uptime 2>/dev/null || printf unknown)"
	user="$(id -un 2>/dev/null || printf unknown)"
	uid="$(id -u 2>/dev/null || printf unknown)"
	groups="$(id -nG 2>/dev/null || id 2>/dev/null || printf unknown)"
	root_note="Non-root run: some root-only checks may be unavailable."
	[ "$uid" = "0" ] && root_note="Running as root: permission checks may differ from unprivileged reality."

	add_finding "Audit execution context" "Info" "High" \
		"OS=$os; kernel=$kernel; arch=$arch; host=$host; uptime=$up; user=$user uid=$uid groups=$groups; $root_note" \
		"Privilege-escalation triage depends on distribution, kernel, identity, group memberships, and whether protected files were readable." \
		"Re-run from the target user account that needs assessment; compare with a root-run inventory only when authorized." \
		"uname, hostname, uptime, id, /etc/os-release"
}

check_sudo() {
	if ! has_cmd sudo; then
		add_finding "sudo command not installed or not in PATH" "Info" "High" \
			"sudo was not found." \
			"sudo-based privilege escalation checks are unavailable on this host or from this PATH." \
			"Confirm whether privilege delegation is handled by sudo, doas, polkit, or another control." \
			"command -v sudo"
		return
	fi

	out="$(sudo -n -l 2>&1 || true)"
	case "$out" in
		*"may run the following commands"*|*"NOPASSWD"*|*"SETENV"*|*"!authenticate"*)
			severity="Medium"
			conf="Medium"
			why="sudo rules can permit direct administrative actions or controlled command execution. Rules with NOPASSWD, SETENV, wildcard arguments, or shell-capable programs require careful review."
			case "$out" in
				*"NOPASSWD"*|*"SETENV"*) severity="High"; conf="High" ;;
			esac
			add_finding "sudo privileges available without prompting" "$severity" "$conf" \
				"sudo -n -l returned rules: $(printf '%s' "$out" | limit_lines 12 | tr '\n' '; ')" \
				"$why" \
				"Apply least privilege, require authentication where practical, avoid SETENV unless necessary, pin exact command paths and arguments, and review shell-capable binaries against GTFOBins or vendor guidance." \
				"sudo -n -l"
			;;
		*"a password is required"*|*"Password is required"*)
			add_finding "sudo privileges may require authentication" "Low" "Medium" \
				"sudo -n -l reported that a password is required." \
				"The user may still have sudo rights, but this non-invasive audit did not prompt for credentials." \
				"Manually run sudo -l during an authorized interactive review and inspect allowed commands." \
				"sudo -n -l"
			;;
		*"not allowed"*|*"not in the sudoers"*)
			add_finding "No non-interactive sudo privileges detected" "Info" "Medium" \
				"sudo -n -l did not return allowed commands." \
				"This lowers sudo-specific risk but does not rule out other privilege delegation paths." \
				"Keep sudoers minimal and audited." \
				"sudo -n -l"
			;;
		*)
			add_finding "sudo privileges inconclusive" "Info" "Low" \
				"sudo -n -l output: $(printf '%s' "$out" | limit_lines 6 | tr '\n' '; ')" \
				"sudo output varies by policy and configuration; inconclusive results need manual review." \
				"Run sudo -l interactively if authorized and inspect /etc/sudoers plus /etc/sudoers.d with appropriate privileges." \
				"sudo -n -l"
			;;
	esac
}

check_groups() {
	groups="$(id -nG 2>/dev/null || true)"
	risky=""
	for g in docker podman lxd lxc libvirt kvm disk shadow adm sudo wheel root systemd-journal; do
		case " $groups " in
			*" $g "*) risky="${risky}${g} " ;;
		esac
	done
	[ -n "$risky" ] || return 0
	add_finding "Membership in high-impact local groups" "Medium" "High" \
		"Current groups include: $(one_line "$risky")" \
		"Some local groups grant broad host access, container control, raw disk access, log access, or administrative delegation. Container-control groups are often equivalent to root on the host if daemon access is unrestricted." \
		"Remove unnecessary memberships, require audited break-glass workflows for admin groups, and restrict container daemon socket access." \
		"id -nG"
}

check_sensitive_permissions() {
	for p in /etc/passwd /etc/shadow /etc/sudoers /etc/group; do
		[ -e "$p" ] || continue
		mode="$(mode_of "$p")"
		owner="$(owner_of "$p")"
		if is_writable_path "$p"; then
			add_finding "Sensitive file is writable by current user: $p" "Critical" "High" \
				"$p mode=$mode owner=$owner current_user=$(id -un 2>/dev/null || printf unknown)" \
				"Write access to identity, password, group, or sudo policy files can directly enable privilege escalation or persistent administrative access." \
				"Restore vendor-default ownership and permissions immediately, investigate why the permission changed, and review recent modifications." \
				"test -w, stat"
		elif is_world_writable "$p"; then
			add_finding "Sensitive file appears world-writable: $p" "Critical" "High" \
				"$p mode=$mode owner=$owner" \
				"World-writable sensitive policy files can allow unprivileged users to alter authentication or authorization." \
				"Restore strict permissions such as root ownership and distro-appropriate modes; validate package integrity." \
				"stat"
		fi
	done

	for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/sudoers.d; do
		[ -e "$d" ] || continue
		if is_writable_path "$d" || is_world_writable "$d"; then
			add_finding "Sensitive configuration directory is writable: $d" "High" "High" \
				"$d mode=$(mode_of "$d") owner=$(owner_of "$d")" \
				"Writable privileged configuration directories can allow users to add or alter jobs or policy snippets executed or trusted by root." \
				"Restrict ownership to root and remove group/world write permissions unless a documented control requires them." \
				"test -w, stat"
		fi
	done
}

check_path_risks() {
	path_value="${PATH:-}"
	[ -n "$path_value" ] || return 0
	empty_seen=0
	writable=""
	relative=""
	oldifs="$IFS"
	IFS=':'
	for d in $path_value; do
		IFS="$oldifs"
		[ -n "$d" ] || { empty_seen=1; IFS=':'; continue; }
		case "$d" in
			/*) : ;;
			*) relative="${relative}${d} " ;;
		esac
		if [ -d "$d" ] && is_writable_path "$d"; then
			writable="${writable}${d}($(mode_of "$d")) "
		fi
		IFS=':'
	done
	IFS="$oldifs"
	if [ "$empty_seen" -eq 1 ] || [ -n "$relative" ]; then
		add_finding "PATH contains relative or empty entries" "Medium" "High" \
			"PATH=$path_value; relative_entries=$(one_line "$relative"); empty_entry=$empty_seen" \
			"Relative or empty PATH entries can cause commands to resolve from the current directory, which is risky when privileged scripts or sudo rules preserve PATH." \
			"Use absolute PATH entries only and set secure_path for privileged execution contexts." \
			"PATH inspection"
	fi
	if [ -n "$writable" ]; then
		add_finding "Writable directory present in PATH" "High" "High" \
			"Writable PATH directories: $(one_line "$writable")" \
			"If privileged scripts or misconfigured sudo rules execute commands without absolute paths, writable PATH directories can enable command hijacking." \
			"Remove writable directories from PATH, make shared binary directories root-owned and non-writable, and use absolute command paths in privileged scripts." \
			"test -w, stat, PATH inspection"
	fi
}

check_suid_sgid() {
	[ "$FAST" -eq 1 ] && return 0
	paths="/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt"
	[ "$FULL" -eq 1 ] && paths="/"
	if ! has_cmd find; then
		return 0
	fi
	list="$(find $paths -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | sort 2>/dev/null | limit_lines 80)"
	[ -n "$list" ] || return 0
	interesting="$(printf '%s\n' "$list" | awk '
		/(bash|dash|sh|zsh|ksh|python|perl|ruby|php|node|vim|vi|nvim|find|cp|tar|rsync|nmap|env|awk|sed|less|more|nano|openssl|socat|nc|netcat)$/ { print }
	')"
	if [ -n "$interesting" ]; then
		add_finding "SUID/SGID shell-capable or file-manipulation binaries found" "High" "Medium" \
			"Interesting SUID/SGID paths: $(printf '%s' "$interesting" | tr '\n' '; ')" \
			"Unexpected SUID/SGID on interpreters, editors, shells, or file tools can be directly dangerous. Some may be legitimate, so ownership, package provenance, and intended mode must be verified." \
			"Remove unnecessary SUID/SGID bits, reinstall affected packages if tampering is suspected, and maintain an approved baseline for privileged binaries." \
			"find -perm -4000/-2000"
	else
		add_finding "SUID/SGID binaries inventory" "Info" "High" \
			"Found SUID/SGID files: $(printf '%s' "$list" | tr '\n' '; ')" \
			"SUID/SGID binaries are normal on Linux, but unexpected additions are a common escalation path." \
			"Compare this list to a known-good baseline for the distribution and installed packages." \
			"find -perm -4000/-2000"
	fi
}

check_capabilities() {
	if ! has_cmd getcap; then
		add_finding "Linux capabilities check unavailable" "Info" "High" \
			"getcap was not found." \
			"File capabilities can grant powerful privileges without SUID bits, so missing tooling leaves a visibility gap." \
			"Install libcap tools in a controlled admin workflow or inspect package baselines." \
			"command -v getcap"
		return 0
	fi
	[ "$FAST" -eq 1 ] && roots="/usr/bin /usr/sbin /bin /sbin" || roots="/usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /opt"
	caps="$(getcap -r $roots 2>/dev/null | sort 2>/dev/null | limit_lines 80)"
	[ -n "$caps" ] || return 0
	danger="$(printf '%s\n' "$caps" | awk '/cap_setuid|cap_setgid|cap_dac_read_search|cap_dac_override|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_net_admin/ {print}')"
	if [ -n "$danger" ]; then
		add_finding "Powerful Linux file capabilities present" "High" "Medium" \
			"Capabilities: $(printf '%s' "$danger" | tr '\n' '; ')" \
			"Capabilities such as cap_setuid, cap_dac_override, cap_sys_admin, and cap_sys_ptrace can bypass important privilege boundaries when assigned to abusable binaries." \
			"Verify each capability is required, remove unnecessary capabilities with setcap -r during an approved change, and compare against package defaults." \
			"getcap -r"
	else
		add_finding "Linux capabilities inventory" "Info" "High" \
			"Capabilities: $(printf '%s' "$caps" | tr '\n' '; ')" \
			"File capabilities are legitimate in many packages but should be baselined." \
			"Review against vendor defaults and monitor for drift." \
			"getcap -r"
	fi
}

check_world_writable() {
	[ "$FAST" -eq 1 ] && return 0
	has_cmd find || return 0
	roots="/tmp /var/tmp /dev/shm /var/www /opt /usr/local /home"
	[ "$FULL" -eq 1 ] && roots="/"
	ww_dirs="$(find $roots -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sort 2>/dev/null | limit_lines 60)"
	if [ -n "$ww_dirs" ]; then
		add_finding "World-writable directories without sticky bit" "Medium" "High" \
			"Directories: $(printf '%s' "$ww_dirs" | tr '\n' '; ')" \
			"World-writable directories without the sticky bit allow users to delete or replace files owned by others, which can affect privileged workflows." \
			"Add the sticky bit where shared write is required, or remove world write permissions." \
			"find -perm -0002 ! -perm -1000"
	fi
	ww_files="$(find $roots -xdev -type f -perm -0002 -print 2>/dev/null | sort 2>/dev/null | limit_lines 60)"
	if [ -n "$ww_files" ]; then
		add_finding "World-writable files found" "Medium" "High" \
			"Files: $(printf '%s' "$ww_files" | tr '\n' '; ')" \
			"World-writable files can be altered by unprivileged users and become dangerous when consumed by privileged services, cron jobs, or administrators." \
			"Remove world write permissions and ensure ownership matches the responsible service or package." \
			"find -perm -0002"
	fi
}

check_cron() {
	has_cmd find || return 0
	cron_paths="/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs"
	writable=""
	scripts=""
	for p in $cron_paths; do
		[ -e "$p" ] || continue
		if is_writable_path "$p" || is_world_writable "$p"; then
			writable="${writable}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		fi
	done
	for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
		[ -d "$d" ] || continue
		found="$(find "$d" -maxdepth 1 -type f \( -writable -o -perm -0002 \) -print 2>/dev/null | limit_lines 30)"
		[ -n "$found" ] && scripts="${scripts}${found}
"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable cron configuration path" "High" "High" \
			"Writable cron paths: $writable" \
			"Writable cron configuration can allow commands to run as root or service users on schedule." \
			"Restrict cron paths to root-owned, non-writable permissions and audit any recently changed jobs." \
			"test -w, stat"
	fi
	if [ -n "$scripts" ]; then
		add_finding "Writable scripts in privileged cron directories" "High" "High" \
			"Writable cron scripts: $(printf '%s' "$scripts" | tr '\n' '; ')" \
			"Cron executes scripts from these directories with elevated context on many systems. Writable scripts can become a direct privilege-escalation path." \
			"Remove write access for non-privileged users and verify script contents from trusted sources." \
			"find cron directories -writable"
	fi
}

check_systemd() {
	if ! has_cmd systemctl; then
		return 0
	fi
	units="$(systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null | awk '{print $1}' | limit_lines 300)"
	[ -n "$units" ] || return 0
	writable_units=""
	writable_execs=""
	for unit in $units; do
		frag="$(systemctl show "$unit" -p FragmentPath --value 2>/dev/null || true)"
		[ -n "$frag" ] && [ "$frag" != "n/a" ] || continue
		if [ -e "$frag" ] && { is_writable_path "$frag" || is_world_writable "$frag"; }; then
			writable_units="${writable_units}${unit}:${frag} mode=$(mode_of "$frag"); "
		fi
		[ "$FAST" -eq 1 ] && continue
		execs="$(systemctl show "$unit" -p ExecStart --value 2>/dev/null | sed 's/[{}]//g' | tr ' ;' '\n' | awk '/^\// {print}' | limit_lines 8)"
		for exe in $execs; do
			[ -e "$exe" ] || continue
			if is_writable_path "$exe" || is_world_writable "$exe"; then
				writable_execs="${writable_execs}${unit}:${exe} mode=$(mode_of "$exe"); "
			fi
		done
	done
	if [ -n "$writable_units" ]; then
		add_finding "Writable systemd unit files" "High" "High" \
			"Writable units: $writable_units" \
			"Writable service unit files can alter commands run by privileged services on restart or boot." \
			"Make unit files root-owned and non-writable by unprivileged users; reload systemd only after approved review." \
			"systemctl show FragmentPath, test -w"
	fi
	if [ -n "$writable_execs" ]; then
		add_finding "Writable executables referenced by systemd services" "High" "High" \
			"Writable service executables: $writable_execs" \
			"Services often run as root or privileged service accounts. Writable executables in ExecStart paths can allow code replacement." \
			"Restore trusted binaries/scripts, restrict write access, and verify package or deployment integrity." \
			"systemctl show ExecStart, test -w"
	fi
}

check_timers() {
	if ! has_cmd systemctl; then
		return 0
	fi
	timers="$(systemctl list-timers --all --no-pager --no-legend 2>/dev/null | limit_lines 40)"
	[ -n "$timers" ] || return 0
	add_finding "Systemd timers present" "Info" "High" \
		"Timers: $(printf '%s' "$timers" | tr '\n' '; ')" \
		"Timers are scheduled execution paths similar to cron. They are usually normal but relevant when paired with writable units or scripts." \
		"Review timer ownership and linked service units during privileged execution audits." \
		"systemctl list-timers"
}

check_processes() {
	if ! has_cmd ps; then
		return 0
	fi
	procs="$(ps -eo user,pid,ppid,comm,args 2>/dev/null | awk 'NR==1 || $1=="root" {print}' | limit_lines 80)"
	[ -n "$procs" ] && add_finding "Root-owned process inventory" "Info" "Medium" \
		"Root processes: $(printf '%s' "$procs" | tr '\n' '; ')" \
		"Root-owned processes define privileged execution surfaces. Writable scripts, unusual interpreters, or user-controlled arguments in these processes deserve manual review." \
		"Inspect unusual root processes and verify referenced files are root-owned and non-writable." \
		"ps -eo user,pid,ppid,comm,args"
}

check_environment() {
	env_names="$(env 2>/dev/null | awk -F= '/^(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB|NODE_PATH|PATH|IFS|BASH_ENV|ENV|SUDO_|KUBECONFIG|AWS_|GOOGLE_|AZURE_|DOCKER_|PODMAN_)/ {print $1}' | sort -u | tr '\n' ' ')"
	[ -n "$env_names" ] || return 0
	add_finding "Interesting environment variables present" "Low" "High" \
		"Variable names only: $(one_line "$env_names")" \
		"Loader, interpreter, cloud, container, and sudo-related environment variables can influence privileged commands or reveal operational context. Values are intentionally not printed." \
		"Avoid preserving risky environment variables into privileged contexts; use sudo env_reset and explicit allowlists." \
		"env variable-name filtering"
}

check_history_indicators() {
	files=""
	for f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.python_history"; do
		[ -e "$f" ] || continue
		meta="$f mode=$(mode_of "$f") owner=$(owner_of "$f")"
		files="${files}${meta}; "
	done
	[ -n "$files" ] || return 0
	add_finding "Shell and tool history files exist" "Low" "High" \
		"$files" \
		"History files sometimes contain credentials or administrative commands. This audit reports metadata only and does not dump contents." \
		"Set restrictive permissions, avoid entering secrets on command lines, and rotate any secrets known to have been typed into shells." \
		"stat history file paths"
}

check_ssh() {
	evidence=""
	for f in /etc/ssh/sshd_config "$HOME/.ssh/config" "$HOME/.ssh/authorized_keys"; do
		[ -r "$f" ] || continue
		case "$f" in
			*/sshd_config)
				hits="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|AuthorizedKeysFile)/ {print}' "$f" 2>/dev/null)"
				;;
			*)
				hits="$f mode=$(mode_of "$f") owner=$(owner_of "$f")"
				;;
		esac
		[ -n "$hits" ] && evidence="${evidence}${f}: $(one_line "$hits"); "
	done
	[ -n "$evidence" ] || return 0
	severity="Info"
	case "$evidence" in
		*"PermitRootLogin yes"*|*"PasswordAuthentication yes"*|*"PermitEmptyPasswords yes"*) severity="Medium" ;;
	esac
	add_finding "SSH configuration risk indicators" "$severity" "Medium" \
		"$evidence" \
		"SSH settings and authorized key permissions affect remote administrative access. Some directives are safe only with compensating controls." \
		"Disable empty passwords, avoid direct root login, prefer key-based authentication with MFA where available, and keep user SSH files private." \
		"awk selected sshd_config directives, stat user SSH files"
}

check_mounts_nfs() {
	mount_data="$(mount 2>/dev/null || safe_read /proc/mounts || true)"
	[ -n "$mount_data" ] || return 0
	nfs="$(printf '%s\n' "$mount_data" | awk '/ type nfs| type nfs4| nfs / {print}' | limit_lines 20)"
	risky="$(printf '%s\n' "$mount_data" | awk '/(rw,|,rw,)/ && /(nosuid|noexec)/ == 0 {print}' | awk '/\/tmp|\/var\/tmp|\/dev\/shm|\/home|\/var\/www|\/opt/ {print}' | limit_lines 30)"
	if [ -n "$nfs" ]; then
		add_finding "NFS mounts detected" "Low" "Medium" \
			"NFS mounts: $(printf '%s' "$nfs" | tr '\n' '; ')" \
			"NFS export options such as no_root_squash or overly broad write access can create privilege risks, but client-side mount data alone does not prove exploitability." \
			"Review server export options, enforce root_squash where appropriate, and restrict writable exports to necessary clients." \
			"mount or /proc/mounts"
	fi
	if [ -n "$risky" ]; then
		add_finding "Writable execution-capable mounts in sensitive locations" "Low" "Medium" \
			"Mounts: $(printf '%s' "$risky" | tr '\n' '; ')" \
			"Writable mounts without nosuid/noexec in shared or application paths may increase impact of other weaknesses." \
			"Consider noexec,nodev,nosuid for temporary and shared writable filesystems after compatibility testing." \
			"mount or /proc/mounts"
	fi
}

check_containers() {
	evidence=""
	[ -f /.dockerenv ] && evidence="${evidence}/.dockerenv present; "
	grep -qaE 'docker|kubepods|containerd|lxc|libpod' /proc/1/cgroup 2>/dev/null && evidence="${evidence}/proc/1/cgroup suggests container; "
	for s in /var/run/docker.sock /run/podman/podman.sock /var/run/crio/crio.sock; do
		[ -e "$s" ] || continue
		evidence="${evidence}${s} mode=$(mode_of "$s") owner=$(owner_of "$s"); "
		if is_writable_path "$s"; then
			add_finding "Writable container daemon socket" "High" "High" \
				"$s is writable by current user; mode=$(mode_of "$s") owner=$(owner_of "$s")" \
				"Write access to container daemon sockets can permit creating privileged containers or mounting host paths in many configurations." \
				"Restrict socket permissions, remove unnecessary daemon group membership, and audit daemon authorization plugins or rootless boundaries." \
				"test -w, stat"
		fi
	done
	if [ -n "$evidence" ]; then
		add_finding "Containerization indicators" "Info" "Medium" \
			"$evidence" \
			"Container context changes the meaning of host findings. Some risks may be container-local unless host mounts, privileged mode, or daemon sockets are exposed." \
			"Validate namespace, mount, capability, and daemon-socket exposure against the intended container security profile." \
			"/.dockerenv, /proc/1/cgroup, socket metadata"
	fi
}

check_configs_exposure() {
	has_cmd find || return 0
	roots="/var/www /srv /opt /etc /home"
	[ "$FAST" -eq 1 ] && roots="/var/www /srv /opt /etc"
	patterns='.*([.]env|wp-config[.]php|config[.]php|settings[.]php|database[.]yml|secrets?[.]ya?ml|credentials?[.]json|id_rsa|backup|[.]bak|[.]old|[.]save|[.]sql|[.]dump)$'
	found="$(find $roots -xdev -type f 2>/dev/null | awk -v pat="$patterns" 'BEGIN{IGNORECASE=1} $0 ~ pat {print}' | limit_lines 80)"
	[ -n "$found" ] || return 0
	add_finding "Credential-like, backup, or local service config filenames found" "Low" "Medium" \
		"Paths only, contents not read: $(printf '%s' "$found" | tr '\n' '; ')" \
		"Config, key, database dump, and backup filenames often point to sensitive material. Filename presence is not proof of exposed secrets." \
		"Restrict permissions, move secrets out of web roots, delete stale backups, and rotate credentials if contents are confirmed exposed." \
		"find filename matching"
}

check_network() {
	if has_cmd ss; then
		listeners="$(ss -lntup 2>/dev/null | limit_lines 80)"
		cmd="ss -lntup"
	elif has_cmd netstat; then
		listeners="$(netstat -lntup 2>/dev/null | limit_lines 80)"
		cmd="netstat -lntup"
	else
		return 0
	fi
	[ -n "$listeners" ] || return 0
	add_finding "Network listeners inventory" "Info" "Medium" \
		"Listeners: $(printf '%s' "$listeners" | tr '\n' '; ')" \
		"Local listeners expose services that may run with elevated privileges or provide administrative surfaces. Listener presence alone is not a vulnerability." \
		"Disable unnecessary services, bind admin interfaces to localhost or management networks, and patch exposed daemons." \
		"$cmd"
}

check_packages_kernel() {
	kernel="$(uname -r 2>/dev/null || true)"
	add_finding "Kernel version risk hint" "Info" "Low" \
		"Kernel version: $kernel" \
		"Kernel age can suggest areas for patch review, but version strings alone do not verify exploitability because distributions backport fixes." \
		"Compare installed kernel security patch level against vendor advisories for the exact distribution and package release." \
		"uname -r"

	if has_cmd dpkg-query; then
		pkgs="$(dpkg-query -W -f='${Package} ${Version}\n' sudo openssh-server systemd docker.io podman 2>/dev/null | limit_lines 30)"
		cmd="dpkg-query"
	elif has_cmd rpm; then
		pkgs="$(rpm -q sudo openssh-server systemd docker podman 2>/dev/null | limit_lines 30)"
		cmd="rpm -q"
	elif has_cmd apk; then
		pkgs="$(apk info -v sudo openssh systemd docker podman 2>/dev/null | limit_lines 30)"
		cmd="apk info"
	else
		pkgs=""
		cmd=""
	fi
	[ -n "$pkgs" ] && add_finding "Selected package versions" "Info" "Medium" \
		"Packages: $(printf '%s' "$pkgs" | tr '\n' '; ')" \
		"Package versions help correlate findings with vendor advisories, but version comparison must be distribution-aware." \
		"Use the distribution security tracker or package manager advisory tooling to confirm patch status." \
		"$cmd"
}

check_privileged_paths() {
	has_cmd find || return 0
	paths="/usr/local/bin /usr/local/sbin /opt /var/www"
	writable=""
	user_owned=""
	for d in $paths; do
		[ -d "$d" ] || continue
		w="$(find "$d" -xdev -type f \( -writable -o -perm -0002 \) -print 2>/dev/null | limit_lines 40)"
		[ -n "$w" ] && writable="${writable}${w}
"
		u="$(find "$d" -xdev -type f -user "$(id -u 2>/dev/null || printf 999999)" -print 2>/dev/null | limit_lines 40)"
		[ -n "$u" ] && user_owned="${user_owned}${u}
"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable files in privileged or service execution paths" "Medium" "High" \
			"Files: $(printf '%s' "$writable" | tr '\n' '; ')" \
			"Files in common service or administrator execution paths can become risky when referenced by cron, systemd, sudo, or operational scripts." \
			"Restrict write permissions and verify whether any privileged task executes these paths." \
			"find -writable"
	fi
	if [ -n "$user_owned" ]; then
		add_finding "Current-user-owned files in privileged-looking paths" "Low" "Medium" \
			"Files: $(printf '%s' "$user_owned" | tr '\n' '; ')" \
			"User-owned files in shared privileged-looking paths are not automatically vulnerable, but they deserve review when privileged automation consumes them." \
			"Move user-managed files to user-owned locations or document and restrict the deployment path." \
			"find -user current_uid"
	fi
}

check_home_permissions() {
	home="${HOME:-}"
	[ -n "$home" ] && [ -d "$home" ] || return 0
	if is_world_writable "$home"; then
		add_finding "Home directory appears world-writable" "Medium" "High" \
			"$home mode=$(mode_of "$home") owner=$(owner_of "$home")" \
			"World-writable home directories can allow tampering with shell startup files, SSH configuration, or user-owned scripts." \
			"Remove world write permissions and review files in the home directory for unauthorized changes." \
			"stat"
	fi
	for f in "$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.zshrc"; do
		[ -e "$f" ] || continue
		if is_world_writable "$f"; then
			add_finding "Shell startup file is world-writable: $f" "Medium" "High" \
				"$f mode=$(mode_of "$f") owner=$(owner_of "$f")" \
				"Writable startup files can execute attacker-controlled commands when the user opens a shell; impact rises if administrators source or switch into the account." \
				"Remove world write permissions and inspect the file contents manually for unauthorized commands." \
			"stat"
		fi
	done
}

check_dynamic_linker() {
	evidence=""
	for p in /etc/ld.so.preload /etc/ld.so.conf; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			add_finding "Writable dynamic linker configuration: $p" "Critical" "High" \
				"$p mode=$(mode_of "$p") owner=$(owner_of "$p")" \
				"Writable linker configuration can force privileged programs to load attacker-controlled shared libraries." \
				"Restore root ownership and strict permissions, verify file contents from a trusted baseline, and investigate recent changes." \
				"test -w, stat"
		fi
	done
	if [ -s /etc/ld.so.preload ]; then
		add_finding "System-wide LD_PRELOAD configuration is active" "High" "Medium" \
			"/etc/ld.so.preload exists and is non-empty; mode=$(mode_of /etc/ld.so.preload) owner=$(owner_of /etc/ld.so.preload)" \
			"System-wide preload is rare on hardened servers and can affect privileged binaries. This is not automatically malicious, but it is high-impact." \
			"Manually validate every referenced library path, ownership, package provenance, and change history." \
			"test -s, stat"
	fi
	for d in /etc/ld.so.conf.d /usr/local/lib /usr/local/lib64; do
		[ -e "$d" ] || continue
		if is_writable_path "$d" || is_world_writable "$d"; then
			add_finding "Writable library search path component: $d" "High" "High" \
				"$d mode=$(mode_of "$d") owner=$(owner_of "$d")" \
				"Writable library search paths can allow library planting when privileged programs load shared objects from those locations." \
				"Restrict write access, keep library directories root-owned, and verify application loader paths." \
				"test -w, stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "Dynamic linker configuration inventory" "Info" "High" \
		"$evidence" \
		"Dynamic linker policy is a high-value review area during privilege-escalation audits." \
		"Keep a baseline of linker configuration and investigate unexpected drift." \
		"stat /etc/ld.so*"
}

check_polkit() {
	has_cmd find || return 0
	paths="/etc/polkit-1/rules.d /usr/share/polkit-1/rules.d /var/lib/polkit-1"
	writable=""
	rules=""
	for d in $paths; do
		[ -e "$d" ] || continue
		if is_writable_path "$d" || is_world_writable "$d"; then
			writable="${writable}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		fi
		[ -d "$d" ] || continue
		found="$(find "$d" -xdev -type f \( -writable -o -perm -0002 \) -print 2>/dev/null)"
		[ -n "$found" ] && writable="${writable}$(printf '%s' "$found" | tr '\n' '; ')"
		readable="$(find "$d" -xdev -type f \( -name '*.rules' -o -name '*.pkla' \) -readable -print 2>/dev/null)"
		[ -n "$readable" ] && rules="${rules}$(printf '%s' "$readable" | tr '\n' '; ')"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable polkit policy path" "High" "High" \
			"$writable" \
			"Polkit rules can authorize privileged desktop, service, and administrative actions. Writable policy paths are high impact." \
			"Restore root ownership, remove unprivileged write access, and audit existing rules for broad allow decisions." \
			"find polkit paths -writable, stat"
	fi
	[ -n "$rules" ] && add_finding "Polkit policy files present" "Info" "Medium" \
		"Policy files: $rules" \
		"Polkit is an enterprise-relevant authorization layer. Broad rules can grant local privilege paths even when sudo is locked down." \
		"Manually review rule logic for Result.YES, broad group grants, and wildcard actions." \
		"find polkit rules"
}

check_pam_policy() {
	has_cmd find || return 0
	[ -d /etc/pam.d ] || return 0
	writable="$(find /etc/pam.d -xdev \( -type f -o -type l \) \( -writable -o -perm -0002 \) -print 2>/dev/null)"
	if [ -n "$writable" ]; then
		add_finding "Writable PAM policy files" "Critical" "High" \
			"Writable PAM files: $(printf '%s' "$writable" | tr '\n' '; ')" \
			"PAM controls authentication for sudo, su, SSH, login, and many services. Writable policy can directly weaken authentication." \
			"Restore root ownership and package-default permissions, then review all recent PAM changes." \
			"find /etc/pam.d -writable"
	fi
	risky="$(grep -RE 'pam_permit[.]so|nullok|pam_exec[.]so|pam_python[.]so' /etc/pam.d 2>/dev/null | awk -F: '$2 !~ /^[[:space:]]*#/' || true)"
	if [ -n "$risky" ]; then
		add_finding "PAM high-risk directives present" "Medium" "Medium" \
			"Directives: $(printf '%s' "$risky" | tr '\n' '; ')" \
			"Some PAM modules and options are legitimate but high-impact. pam_permit, nullok, and executable PAM hooks require careful justification." \
			"Validate each directive against the authentication design and remove permissive options that are not explicitly required." \
			"grep selected PAM directives"
	fi
}

check_ssh_key_permissions() {
	home="${HOME:-}"
	[ -n "$home" ] && [ -d "$home/.ssh" ] || return 0
	evidence=""
	for f in $(find "$home/.ssh" -maxdepth 1 -type f \( -name 'id_*' -o -name '*_rsa' -o -name '*_ed25519' -o -name '*_ecdsa' -o -name 'authorized_keys' -o -name 'config' \) -print 2>/dev/null | sort -u); do
		[ -e "$f" ] || continue
		case "$f" in
			*.pub|*/known_hosts) continue ;;
		esac
		mode="$(mode_of "$f")"
		owner="$(owner_of "$f")"
		evidence="${evidence}${f} mode=$mode owner=$owner; "
		if is_world_writable "$f"; then
			add_finding "SSH file is world-writable: $f" "High" "High" \
				"$f mode=$mode owner=$owner" \
				"Writable SSH keys or authorization files can allow tampering with login trust or client behavior." \
				"Restrict private keys to 600 and authorized_keys/config to user-writable only." \
				"stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "SSH key and client trust metadata" "Low" "High" \
		"$evidence" \
		"SSH key metadata helps identify weak local key hygiene without printing key material." \
		"Ensure private keys are not group/world readable and protect authorized_keys from unauthorized modification." \
		"stat ~/.ssh files"
}

check_security_tooling() {
	present=""
	missing=""
	for c in auditctl ausearch getenforce sestatus aa-status osqueryi falco wazuh-control ossec-control semanage; do
		if has_cmd "$c"; then
			present="${present}${c} "
		else
			missing="${missing}${c} "
		fi
	done
	evidence="present=$(one_line "$present"); missing=$(one_line "$missing")"
	add_finding "Defensive security tooling visibility" "Info" "Medium" \
		"$evidence" \
		"Enterprise red-team validation depends on host telemetry. Missing audit, MAC, EDR, or query tooling can reduce detection and response visibility." \
		"Confirm expected endpoint controls are installed, running, centrally managed, and generating events for privileged activity." \
		"command -v selected security tools"
}

check_identity_integration() {
	evidence=""
	for p in /etc/sssd/sssd.conf /etc/krb5.conf /etc/samba/smb.conf /etc/realmd.conf /etc/nsswitch.conf; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			add_finding "Writable identity or domain integration config: $p" "High" "High" \
				"$p mode=$(mode_of "$p") owner=$(owner_of "$p")" \
				"Identity integration files influence domain login, name service resolution, Kerberos, and group mapping. Writable config can redirect or weaken trust decisions." \
				"Restore strict permissions, validate domain settings, and compare to managed configuration baselines." \
				"test -w, stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "Identity and domain integration metadata" "Info" "Medium" \
		"$evidence" \
		"Domain and identity integration changes privilege boundaries through group mapping, sudo policy sources, and authentication flows." \
		"Review SSSD, Kerberos, Samba, NSS, and realmd configuration under change control." \
		"stat identity config files"
}

check_local_credential_stores() {
	home="${HOME:-}"
	[ -n "$home" ] || return 0
	evidence=""
	for p in "$home/.aws/credentials" "$home/.aws/config" "$home/.azure" "$home/.config/gcloud" "$home/.docker/config.json" "$home/.kube/config" "$home/.netrc" "$home/.npmrc" "$home/.pypirc"; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_world_writable "$p"; then
			add_finding "Credential store path is world-writable: $p" "High" "High" \
				"$p mode=$(mode_of "$p") owner=$(owner_of "$p")" \
				"Writable credential store paths can let local users alter cloud, registry, container, or Kubernetes client trust and authentication behavior." \
				"Restrict permissions and rotate credentials if tampering is suspected." \
				"stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "Local cloud, registry, and orchestration credential stores" "Low" "High" \
		"$evidence" \
		"Credential store presence is common on admin workstations and CI hosts. This audit reports metadata only and does not read secrets." \
		"Keep credential files private, prefer short-lived tokens, and ensure workstation or CI secrets are scoped least-privilege." \
		"stat known credential paths"
}

check_accounts_policy() {
	evidence=""
	if [ -r /etc/passwd ]; then
		users="$(awk -F: '($3 == 0) {print $1 " uid=0 shell=" $7} ($3 >= 1000 && $7 !~ /(nologin|false)$/) {print $1 " uid=" $3 " shell=" $7}' /etc/passwd 2>/dev/null | tr '\n' '; ')"
		[ -n "$users" ] && evidence="${evidence}login-capable and uid0 accounts: $users"
		uid0_count="$(awk -F: '($3 == 0) {c++} END {print c+0}' /etc/passwd 2>/dev/null)"
		if [ "$uid0_count" -gt 1 ]; then
			add_finding "Multiple UID 0 accounts exist" "High" "High" \
				"UID 0 accounts: $(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null | tr '\n' '; ')" \
				"Every UID 0 account has root-equivalent local privileges. Extra UID 0 accounts are often unnecessary and high impact." \
				"Keep only required UID 0 accounts, document exceptions, and investigate unexpected root-equivalent identities." \
				"awk /etc/passwd"
		fi
		empty_pw="$(awk -F: '($2 == "") {print $1}' /etc/passwd 2>/dev/null | tr '\n' '; ')"
		if [ -n "$empty_pw" ]; then
			add_finding "Accounts with empty password field in /etc/passwd" "High" "High" \
				"Accounts: $empty_pw" \
				"Empty password fields in /etc/passwd can indicate severely weakened local authentication depending on PAM and shadow configuration." \
				"Lock or set passwords for affected accounts and verify shadow/PAM policy." \
				"awk /etc/passwd"
		fi
	fi
	if [ -r /etc/login.defs ]; then
		policy="$(awk '/^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD)[[:space:]]/ {print}' /etc/login.defs 2>/dev/null | tr '\n' '; ')"
		[ -n "$policy" ] && evidence="${evidence}login.defs: $policy"
	fi
	[ -n "$evidence" ] && add_finding "Local account and password policy inventory" "Info" "High" \
		"$evidence" \
		"Local users, shells, UID 0 identities, and password policy shape the attack surface for lateral movement and privilege escalation." \
		"Disable stale accounts, avoid shared administrator accounts, and enforce organization password and shell policy." \
		"awk /etc/passwd, /etc/login.defs"
}

check_auth_policy_files() {
	evidence=""
	for p in /etc/security/access.conf /etc/security/faillock.conf /etc/security/limits.conf /etc/security/pwquality.conf /etc/security/opasswd /etc/subuid /etc/subgid /etc/shells; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			add_finding "Writable authentication or account policy file: $p" "High" "High" \
				"$p mode=$(mode_of "$p") owner=$(owner_of "$p")" \
				"Authentication and account policy files influence login restrictions, password quality, resource limits, subordinate IDs, and valid shells." \
				"Restore root ownership and package-default permissions, then review policy contents under change control." \
				"test -w, stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "Authentication policy file metadata" "Info" "High" \
		"$evidence" \
		"These files are common enterprise hardening and account-control surfaces. Metadata helps spot drift without reading secrets." \
		"Baseline ownership and permissions and validate policy with administrators." \
		"stat /etc/security and account policy files"
}

check_sudoers_files() {
	evidence=""
	for p in /etc/sudoers /etc/sudoers.d; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
	done
	if [ -d /etc/sudoers.d ] && has_cmd find; then
		files="$(find /etc/sudoers.d -maxdepth 1 -type f -print 2>/dev/null | sort 2>/dev/null)"
		[ -n "$files" ] && evidence="${evidence}sudoers.d files: $(printf '%s' "$files" | tr '\n' '; ')"
		writable="$(find /etc/sudoers.d -maxdepth 1 \( -type f -o -type d \) \( -writable -o -perm -0002 \) -print 2>/dev/null)"
		if [ -n "$writable" ]; then
			add_finding "Writable sudoers include path" "Critical" "High" \
				"Writable sudoers paths: $(printf '%s' "$writable" | tr '\n' '; ')" \
				"Writable sudoers policy can grant direct administrative command execution." \
				"Restore root ownership and strict permissions, validate with visudo, and audit recent changes." \
				"find /etc/sudoers.d -writable"
		fi
	fi
	[ -n "$evidence" ] && add_finding "Sudo policy file metadata" "Info" "High" \
		"$evidence" \
		"Sudo policy files are central privilege-delegation controls. Metadata and include inventory help guide manual review." \
		"Review sudoers with visudo, remove broad wildcards, and keep least-privilege command rules." \
		"stat /etc/sudoers /etc/sudoers.d"
}

check_doas_pkexec() {
	evidence=""
	if has_cmd doas || [ -e /etc/doas.conf ]; then
		[ -e /etc/doas.conf ] && evidence="${evidence}/etc/doas.conf mode=$(mode_of /etc/doas.conf) owner=$(owner_of /etc/doas.conf); "
		if [ -e /etc/doas.conf ] && { is_writable_path /etc/doas.conf || is_world_writable /etc/doas.conf; }; then
			add_finding "Writable doas policy file" "Critical" "High" \
				"/etc/doas.conf mode=$(mode_of /etc/doas.conf) owner=$(owner_of /etc/doas.conf)" \
				"doas policy can authorize privileged command execution. Writable policy is root-equivalent in many configurations." \
				"Restore root ownership and strict permissions, then review permit rules." \
				"test -w, stat /etc/doas.conf"
		fi
	fi
	if has_cmd pkexec; then
		meta="$(command -v pkexec 2>/dev/null)"
		[ -n "$meta" ] && evidence="${evidence}pkexec=$(command -v pkexec) mode=$(mode_of "$meta") owner=$(owner_of "$meta"); "
	fi
	[ -n "$evidence" ] && add_finding "Alternative privilege delegation surfaces" "Info" "Medium" \
		"$evidence" \
		"doas and pkexec can grant privileged actions independently of sudo. Presence is not a vulnerability, but policy should be reviewed." \
		"Review doas and polkit policies for broad grants and ensure binaries are package-managed and patched." \
		"command -v doas/pkexec, stat"
}

check_kernel_hardening() {
	evidence=""
	for p in /proc/sys/kernel/randomize_va_space /proc/sys/kernel/yama/ptrace_scope /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict /proc/sys/fs/protected_hardlinks /proc/sys/fs/protected_symlinks /proc/sys/fs/suid_dumpable /proc/sys/kernel/core_pattern; do
		[ -r "$p" ] || continue
		val="$(tr '\n' ' ' < "$p" 2>/dev/null | sed 's/[[:space:]][[:space:]]*/ /g; s/ $//')"
		evidence="${evidence}${p}=${val}; "
	done
	[ -n "$evidence" ] && add_finding "Kernel hardening and namespace posture" "Info" "Medium" \
		"$evidence" \
		"Kernel sysctls influence exploit reliability, information disclosure, namespace abuse, hardlink/symlink protections, core dumps, and process inspection." \
		"Compare these settings against the organization baseline and distribution hardening guidance." \
		"read /proc/sys selected hardening keys"
}

check_linux_security_modules() {
	evidence=""
	[ -r /sys/kernel/security/lsm ] && evidence="${evidence}lsm=$(safe_read /sys/kernel/security/lsm | tr '\n' ' '); "
	if has_cmd getenforce; then
		evidence="${evidence}SELinux=$(getenforce 2>/dev/null); "
	fi
	if has_cmd aa-status; then
		evidence="${evidence}AppArmor=$(aa-status 2>/dev/null | head -n 5 | tr '\n' ' '); "
	elif [ -d /sys/kernel/security/apparmor ]; then
		evidence="${evidence}AppArmor filesystem present; "
	fi
	[ -n "$evidence" ] && add_finding "Linux security module posture" "Info" "Medium" \
		"$evidence" \
		"SELinux, AppArmor, and other LSMs can contain privilege-escalation impact and improve detection context." \
		"Validate expected LSM enforcement mode and profile coverage for exposed services." \
		"getenforce, aa-status, /sys/kernel/security/lsm"
}

check_firewall_network_posture() {
	evidence=""
	if has_cmd ip; then
		routes="$(ip route 2>/dev/null | tr '\n' '; ')"
		addrs="$(ip -o addr show 2>/dev/null | awk '{print $2 " " $3 " " $4}' | tr '\n' '; ')"
		[ -n "$routes" ] && evidence="${evidence}routes: $routes"
		[ -n "$addrs" ] && evidence="${evidence}addresses: $addrs"
	fi
	for c in nft iptables ufw firewall-cmd; do
		if has_cmd "$c"; then
			case "$c" in
				nft) data="$(nft list ruleset 2>/dev/null | head -n 80 | tr '\n' '; ')" ;;
				iptables) data="$(iptables -S 2>/dev/null | head -n 80 | tr '\n' '; ')" ;;
				ufw) data="$(ufw status 2>/dev/null | tr '\n' '; ')" ;;
				firewall-cmd) data="$(firewall-cmd --state 2>/dev/null; firewall-cmd --get-active-zones 2>/dev/null)" ;;
			esac
			evidence="${evidence}${c}: $(one_line "$data"); "
		fi
	done
	[ -n "$evidence" ] && add_finding "Network routing and firewall posture" "Info" "Medium" \
		"$evidence" \
		"Network exposure and firewall state help prioritize local privilege findings on externally reachable or management-connected hosts." \
		"Disable unnecessary interfaces/services and validate firewall policy against host role." \
		"ip route, ip addr, nft/iptables/ufw/firewall-cmd"
}

check_process_anomalies() {
	has_cmd ps || return 0
	evidence=""
	deleted=""
	if has_cmd find; then
		deleted="$(find /proc/[0-9]*/exe -type l -lname '*deleted*' -print 2>/dev/null | tr '\n' '; ')"
	fi
	[ -n "$deleted" ] && evidence="${evidence}deleted executables: $deleted"
	root_interpreters="$(ps -eo user,pid,ppid,comm,args 2>/dev/null | awk '$1=="root" && $4 ~ /(python|perl|ruby|php|node|bash|sh|zsh|nc|socat|openssl)/ {print}' | tr '\n' '; ')"
	[ -n "$root_interpreters" ] && evidence="${evidence}root interpreter/network helper processes: $root_interpreters"
	if [ -n "$evidence" ]; then
		add_finding "Interesting privileged process indicators" "Medium" "Medium" \
			"$evidence" \
			"Root-owned interpreters, network helpers, and deleted executable mappings can be normal during operations, but they are high-value review targets." \
			"Validate process owners, command lines, service definitions, and deployment history." \
			"ps, find /proc/*/exe"
	fi
}

check_sessions_and_ipc() {
	evidence=""
	for c in w who last loginctl; do
		if has_cmd "$c"; then
			case "$c" in
				last) data="$(last -n 10 2>/dev/null | tr '\n' '; ')" ;;
				loginctl) data="$(loginctl list-sessions --no-legend 2>/dev/null | tr '\n' '; ')" ;;
				*) data="$("$c" 2>/dev/null | tr '\n' '; ')" ;;
			esac
			[ -n "$data" ] && evidence="${evidence}${c}: $(one_line "$data"); "
		fi
	done
	for d in /run/screen /var/run/screen /tmp/tmux-*; do
		[ -e "$d" ] && evidence="${evidence}session path $d mode=$(mode_of "$d") owner=$(owner_of "$d"); "
	done
	[ -n "$evidence" ] && add_finding "Interactive session and IPC inventory" "Info" "Medium" \
		"$evidence" \
		"Active sessions, terminal multiplexers, and IPC paths can affect operational risk and manual validation scope." \
		"Review unexpected active users or stale privileged sessions during an authorized assessment." \
		"w, who, last, loginctl, stat screen/tmux paths"
}

check_startup_persistence_paths() {
	has_cmd find || return 0
	paths="/etc/profile /etc/profile.d /etc/bash.bashrc /etc/zsh /etc/environment /etc/rc.local /etc/rc.d /etc/init.d /etc/update-motd.d"
	writable=""
	inventory=""
	for p in $paths; do
		[ -e "$p" ] || continue
		inventory="${inventory}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			writable="${writable}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		fi
	done
	for d in /etc/profile.d /etc/init.d /etc/update-motd.d; do
		[ -d "$d" ] || continue
		found="$(find "$d" -maxdepth 1 \( -type f -o -type l \) \( -writable -o -perm -0002 \) -print 2>/dev/null)"
		[ -n "$found" ] && writable="${writable}$(printf '%s' "$found" | tr '\n' '; ')"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable shell startup or legacy init path" "High" "High" \
			"$writable" \
			"Shell startup, MOTD, rc.local, and init scripts can execute in privileged or administrator contexts depending on system configuration." \
			"Restore root ownership, remove unprivileged write access, and review content from trusted baselines." \
			"find startup/init paths -writable"
	fi
	[ -n "$inventory" ] && add_finding "Startup and legacy init path inventory" "Info" "Medium" \
		"$inventory" \
		"Startup and legacy init paths are useful persistence and privilege-boundary review areas." \
		"Keep these paths root-owned, monitored, and under configuration management." \
		"stat startup/init paths"
}

check_logrotate_and_backup_jobs() {
	has_cmd find || return 0
	evidence=""
	writable=""
	for p in /etc/logrotate.conf /etc/logrotate.d /etc/anacrontab /var/spool/anacron; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			writable="${writable}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		fi
	done
	for d in /etc/logrotate.d /var/backups /backup /backups; do
		[ -d "$d" ] || continue
		found="$(find "$d" -maxdepth 2 \( -writable -o -perm -0002 \) -print 2>/dev/null)"
		[ -n "$found" ] && writable="${writable}$(printf '%s' "$found" | tr '\n' '; ')"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable logrotate, anacron, or backup path" "Medium" "High" \
			"$writable" \
			"Writable maintenance-job configuration or backup paths can become dangerous when privileged jobs consume user-controlled files." \
			"Restrict write access and validate which privileged jobs read or execute from these paths." \
			"find logrotate/anacron/backup paths -writable"
	fi
	[ -n "$evidence" ] && add_finding "Logrotate, anacron, and backup metadata" "Info" "Medium" \
		"$evidence" \
		"Maintenance jobs and backups often run with elevated privileges and can expose sensitive files if permissions drift." \
		"Review job configuration and backup retention permissions." \
		"stat logrotate/anacron/backup paths"
}

check_interesting_binaries() {
	present=""
	for c in gcc cc make gdb strace ltrace perf tcpdump nmap nc netcat socat curl wget python python3 perl ruby php node openssl ssh scp rsync docker podman kubectl helm terraform ansible ansible-playbook aws az gcloud mysql psql sqlite3 redis-cli mongo; do
		if has_cmd "$c"; then
			present="${present}${c}=$(command -v "$c" 2>/dev/null); "
		fi
	done
	[ -n "$present" ] && add_finding "Interesting offensive, admin, and developer tooling available" "Info" "High" \
		"$present" \
		"Compilers, debuggers, network tools, cloud CLIs, orchestration CLIs, and interpreters can increase post-exploitation options if an attacker already has access." \
		"Restrict unnecessary tooling on production systems and monitor use of admin and cloud CLIs." \
		"command -v selected tools"
}

check_interpreter_permissions() {
	writable=""
	for c in sh bash dash zsh python python3 perl ruby php node awk sed find tar cp rsync env; do
		path="$(command -v "$c" 2>/dev/null || true)"
		[ -n "$path" ] && [ -e "$path" ] || continue
		if is_writable_path "$path" || is_world_writable "$path"; then
			writable="${writable}${c}=$path mode=$(mode_of "$path") owner=$(owner_of "$path"); "
		fi
	done
	[ -n "$writable" ] && add_finding "Writable interpreter or command utility in PATH" "High" "High" \
		"$writable" \
		"Writable interpreters or core utilities can allow command replacement and affect privileged scripts that call them." \
		"Restore package-managed ownership and permissions and investigate filesystem integrity." \
		"command -v, test -w, stat"
}

check_acl_and_attributes() {
	evidence=""
	if has_cmd getfacl && has_cmd find && [ "$FAST" -eq 0 ]; then
		acls="$(find /etc /usr/local /opt -xdev -type f -perm -002 -o -type f -writable 2>/dev/null | head -n 50 | while IFS= read -r f; do getfacl -cp "$f" 2>/dev/null | awk -v file="$f" '/^user:|^group:/ && $0 ~ /w/ {print file ":" $0}'; done | tr '\n' '; ')"
		[ -n "$acls" ] && evidence="${evidence}ACL write grants: $acls"
	fi
	if has_cmd lsattr; then
		attrs="$(lsattr -d /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null | tr '\n' '; ')"
		[ -n "$attrs" ] && evidence="${evidence}attributes: $attrs"
	fi
	[ -n "$evidence" ] && add_finding "Filesystem ACL and attribute indicators" "Info" "Low" \
		"$evidence" \
		"ACLs and extended attributes can override simple mode-bit assumptions or indicate tamper-resistant controls." \
		"Review non-standard write ACLs and confirm immutable/append-only attributes are intentional." \
		"getfacl, lsattr"
}

check_service_config_files() {
	has_cmd find || return 0
	roots="/etc/nginx /etc/apache2 /etc/httpd /etc/mysql /etc/postgresql /etc/redis /etc/mongodb.conf /etc/php /var/www /srv/www"
	evidence=""
	writable=""
	for p in $roots; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			writable="${writable}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		fi
	done
	for d in /etc/nginx /etc/apache2 /etc/httpd /etc/mysql /etc/postgresql /etc/redis /etc/php /var/www /srv/www; do
		[ -d "$d" ] || continue
		found="$(find "$d" -xdev -type f \( -writable -o -perm -0002 \) -print 2>/dev/null)"
		[ -n "$found" ] && writable="${writable}$(printf '%s' "$found" | tr '\n' '; ')"
	done
	if [ -n "$writable" ]; then
		add_finding "Writable web or database service configuration" "Medium" "High" \
			"$writable" \
			"Writable service configuration can alter process behavior, load modules, expose credentials, or change files executed by privileged services." \
			"Restrict write permissions, validate deployment ownership, and reload services only after approved review." \
			"find service configs -writable"
	fi
	[ -n "$evidence" ] && add_finding "Web and database service configuration metadata" "Info" "Medium" \
		"$evidence" \
		"Local service configuration often contains high-value privilege and credential boundaries. This audit reports metadata only." \
		"Review permissions, included files, and secret handling for local services." \
		"stat service config roots"
}

check_ci_cd_and_build_agents() {
	evidence=""
	for p in /etc/jenkins /var/lib/jenkins /opt/jenkins /home/gitlab-runner /etc/gitlab-runner /var/lib/gitlab-runner /opt/actions-runner /srv/buildkite-agent /etc/buildkite-agent /var/lib/buildkite-agent /etc/teamcity-agent /opt/teamcity-agent; do
		[ -e "$p" ] || continue
		evidence="${evidence}${p} mode=$(mode_of "$p") owner=$(owner_of "$p"); "
		if is_writable_path "$p" || is_world_writable "$p"; then
			add_finding "Writable CI/CD or build-agent path: $p" "High" "High" \
				"$p mode=$(mode_of "$p") owner=$(owner_of "$p")" \
				"Build agents often hold deployment credentials and execute automation. Writable agent paths can be high-impact." \
				"Restrict write permissions, isolate runners, and rotate credentials if tampering is suspected." \
				"test -w, stat"
		fi
	done
	[ -n "$evidence" ] && add_finding "CI/CD and build-agent metadata" "Info" "Medium" \
		"$evidence" \
		"CI/CD agents frequently bridge local host access to cloud, registry, and production deployment privileges." \
		"Review runner isolation, secrets scoping, and local filesystem permissions." \
		"stat known CI/CD paths"
}

check_cloud_instance_metadata() {
	evidence=""
	for p in /sys/class/dmi/id/product_uuid /sys/class/dmi/id/product_name /sys/class/dmi/id/sys_vendor; do
		[ -r "$p" ] || continue
		val="$(safe_read "$p" | tr '\n' ' ')"
		evidence="${evidence}${p}=$(one_line "$val"); "
	done
	for c in cloud-init ec2metadata google_metadata_script_runner waagent; do
		has_cmd "$c" && evidence="${evidence}${c}=$(command -v "$c"); "
	done
	[ -d /var/lib/cloud ] && evidence="${evidence}/var/lib/cloud mode=$(mode_of /var/lib/cloud) owner=$(owner_of /var/lib/cloud); "
	[ -n "$evidence" ] && add_finding "Cloud and virtualization metadata indicators" "Info" "Low" \
		"$evidence" \
		"Cloud or virtualization context changes identity, metadata-service, and lateral movement considerations. No metadata service queries are made." \
		"Validate IMDS hardening, instance roles, and cloud-init permissions using cloud-provider approved methods." \
		"read local DMI and cloud-init metadata paths"
}

check_active_write_validation() {
	[ "$ACTIVE" -eq 1 ] || return 0
	paths="/tmp /var/tmp /dev/shm /usr/local/bin /usr/local/sbin /opt /var/www /srv /etc/profile.d /etc/cron.d /etc/systemd/system /usr/local/lib /usr/local/lib64"
	proven=""
	failed=""
	for d in $paths; do
		[ -d "$d" ] || continue
		if active_write_probe_dir "$d"; then
			proven="${proven}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		elif [ -w "$d" ]; then
			failed="${failed}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		fi
	done
	if [ -n "$proven" ]; then
		add_finding "Active write validation succeeded in sensitive paths" "High" "High" \
			"$proven" \
			"Linbean created and removed marker files in these paths, proving current-user write access. Impact depends on whether privileged users or services consume files there." \
			"Remove unneeded write access, verify ownership, and review privileged automation that reads or executes from these paths." \
			"--active marker file create/remove"
	fi
	if [ -n "$failed" ]; then
		add_finding "Writable-looking paths rejected active marker writes" "Info" "Medium" \
			"$failed" \
			"Mode bits or access tests suggested possible write access, but active marker creation failed. ACLs, mount policy, sandboxing, or race conditions may explain the difference." \
			"Manually validate permissions and mount policy if these paths matter to the assessment." \
			"--active marker file create/remove"
	fi
}

check_active_tmp_execution() {
	[ "$ACTIVE" -eq 1 ] || return 0
	exec_ok=""
	noexec=""
	for d in /tmp /var/tmp /dev/shm "$TMPDIR"; do
		[ -d "$d" ] || continue
		case " $exec_ok $noexec " in *" $d "*) continue ;; esac
		if active_exec_probe_dir "$d"; then
			exec_ok="${exec_ok}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		elif active_write_probe_dir "$d"; then
			noexec="${noexec}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		fi
	done
	if [ -n "$exec_ok" ]; then
		add_finding "Active execution allowed from temporary writable paths" "Low" "High" \
			"$exec_ok" \
			"Linbean created, executed, and removed a harmless marker script from these temporary paths. This is common, but noexec mounts can reduce script-based abuse after compromise." \
			"Consider noexec,nodev,nosuid for temporary filesystems after compatibility testing." \
			"--active marker script execution"
	fi
	if [ -n "$noexec" ]; then
		add_finding "Temporary paths allow writes but blocked marker execution" "Info" "High" \
			"$noexec" \
			"Marker creation succeeded but execution did not, suggesting noexec or equivalent policy is limiting direct execution." \
			"Keep noexec policy where compatible and validate coverage for all temporary filesystems." \
			"--active marker script execution"
	fi
}

check_active_path_hijack() {
	[ "$ACTIVE" -eq 1 ] || return 0
	path_value="${PATH:-}"
	[ -n "$path_value" ] || return 0
	oldifs="$IFS"
	IFS=':'
	proven=""
	for d in $path_value; do
		IFS="$oldifs"
		[ -n "$d" ] && [ -d "$d" ] || { IFS=':'; continue; }
		marker="$d/linbean_probe_cmd_$$"
		if ({ printf '%s\n' '#!/bin/sh' 'exit 24' > "$marker"; } 2>/dev/null) && chmod 700 "$marker" 2>/dev/null; then
			PATH="$d:$PATH" linbean_probe_cmd_$$ >/dev/null 2>&1
			rc="$?"
			rm -f "$marker" 2>/dev/null || true
			[ "$rc" -eq 24 ] && proven="${proven}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		fi
		rm -f "$marker" 2>/dev/null || true
		IFS=':'
	done
	IFS="$oldifs"
	[ -n "$proven" ] && add_finding "Active PATH hijack feasibility validated" "High" "High" \
		"$proven" \
		"Linbean created, resolved through PATH, executed, and removed a harmless marker command from these directories. If privileged scripts rely on PATH, this can become dangerous." \
		"Remove writable directories from PATH, set secure_path for sudo, and use absolute command paths in privileged automation." \
		"--active PATH marker command"
}

check_active_config_sibling_writes() {
	[ "$ACTIVE" -eq 1 ] || return 0
	parents="/etc /etc/systemd /etc/systemd/system /etc/cron.d /etc/logrotate.d /etc/sudoers.d /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d /etc/nginx /etc/apache2 /etc/mysql /etc/postgresql /etc/redis"
	proven=""
	for d in $parents; do
		[ -d "$d" ] || continue
		if active_write_probe_dir "$d"; then
			proven="${proven}${d} mode=$(mode_of "$d") owner=$(owner_of "$d"); "
		fi
	done
	[ -n "$proven" ] && add_finding "Active privileged configuration directory write validated" "Critical" "High" \
		"$proven" \
		"Linbean created and removed marker files in privileged configuration directories. This can allow policy, service, scheduled-task, or application behavior changes." \
		"Immediately restrict directory permissions, inspect recent changes, and validate package integrity." \
		"--active marker file create/remove in config directories"
}

check_active_runtime_socket_access() {
	[ "$ACTIVE" -eq 1 ] || return 0
	evidence=""
	if [ -S /var/run/docker.sock ] && has_cmd docker; then
		out="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
		[ -n "$out" ] && evidence="${evidence}docker daemon API reachable via docker CLI, server_version=$out; "
	fi
	if [ -S /run/podman/podman.sock ] && has_cmd podman; then
		out="$(podman info --format '{{.Host.OCIRuntime.Name}}' 2>/dev/null || true)"
		[ -n "$out" ] && evidence="${evidence}podman service reachable via podman CLI, runtime=$out; "
	fi
	[ -n "$evidence" ] && add_finding "Active container runtime API access validated" "High" "High" \
		"$evidence" \
		"Container runtime API access can be root-equivalent on many hosts, especially when privileged containers or host mounts are permitted." \
		"Restrict runtime socket access and review daemon authorization, rootless boundaries, and group membership." \
		"--active docker/podman metadata query"
}

build_text_report() {
	host="$(hostname 2>/dev/null || uname -n 2>/dev/null || printf unknown)"
	mode="standard"
	[ "$FAST" -eq 1 ] && mode="fast"
	[ "$FULL" -eq 1 ] && mode="full"

	{
		printf '%s\n' "$(color bold)$(color cyan)LINBEAN PRIVILEGE AUDIT$(color reset)"
		printf '%s\n' "$(rule '=')"
		printf '  %-14s %s\n' "Version:" "$VERSION"
		printf '  %-14s %s\n' "Host:" "$host"
		printf '  %-14s %s\n' "Started:" "$START_TS"
		printf '  %-14s %s\n' "Mode:" "$mode"
		printf '  %-14s %s\n' "Safety:" "read-only checks; no secret contents printed"
		printf '%s\n\n' "$(rule '=')"

		printf '%sRisk overview%s\n' "$(color bold)" "$(color reset)"
		printf '  %-12s %5s\n' "Severity" "Count"
		printf '  %-12s %5s\n' "--------" "-----"
		printf '  %-12s %5s\n' "Critical" "$COUNTS_CRITICAL"
		printf '  %-12s %5s\n' "High" "$COUNTS_HIGH"
		printf '  %-12s %5s\n' "Medium" "$COUNTS_MEDIUM"
		printf '  %-12s %5s\n' "Low" "$COUNTS_LOW"
		printf '  %-12s %5s\n' "Info" "$COUNTS_INFO"
		printf '  %-12s %5s\n\n' "Total" "$FINDING_COUNT"

		printf '%sTop actionable findings%s\n' "$(color bold)" "$(color reset)"
		printf '%s\n' "$(rule '-')"
		if [ -n "$TOP_FINDINGS_TEXT" ]; then
			printf '%s' "$TOP_FINDINGS_TEXT"
		else
			printf '  No Critical, High, or Medium findings were detected by these non-invasive checks.\n\n'
		fi

		printf '%sDetailed findings%s\n' "$(color bold)" "$(color reset)"
		printf '%s' "$FINDINGS_TEXT"

		printf '%sFinal summary%s\n' "$(color bold)" "$(color reset)"
		printf '%s\n' "$(rule '-')"
		printf '  %-12s %5s\n' "Critical" "$COUNTS_CRITICAL"
		printf '  %-12s %5s\n' "High" "$COUNTS_HIGH"
		printf '  %-12s %5s\n' "Medium" "$COUNTS_MEDIUM"
		printf '  %-12s %5s\n' "Low" "$COUNTS_LOW"
		printf '  %-12s %5s\n' "Info" "$COUNTS_INFO"
		printf '  %-12s %5s\n' "Total" "$FINDING_COUNT"
	} 
}

build_json_report() {
	host="$(hostname 2>/dev/null || uname -n 2>/dev/null || printf unknown)"
	printf '{'
	printf '"tool":"linbean.sh",'
	printf '"version":"%s",' "$(json_escape "$VERSION")"
	printf '"started":"%s",' "$(json_escape "$START_TS")"
	printf '"host":"%s",' "$(json_escape "$host")"
	printf '"mode":{"full":%s,"fast":%s,"quiet":%s},' "$FULL" "$FAST" "$QUIET"
	printf '"summary":{"total":%s,"critical":%s,"high":%s,"medium":%s,"low":%s,"info":%s},' \
		"$FINDING_COUNT" "$COUNTS_CRITICAL" "$COUNTS_HIGH" "$COUNTS_MEDIUM" "$COUNTS_LOW" "$COUNTS_INFO"
	printf '"findings":[%s]' "$FINDINGS_JSON"
	printf '}\n'
}

build_markdown_report() {
	host="$(hostname 2>/dev/null || uname -n 2>/dev/null || printf unknown)"
	mode="standard"
	[ "$FAST" -eq 1 ] && mode="fast"
	[ "$FULL" -eq 1 ] && mode="full"

	{
		printf '# Linbean Privilege Audit\n\n'
		printf '| Field | Value |\n'
		printf '|---|---|\n'
		printf '| Version | %s |\n' "$(md_escape_table "$VERSION")"
		printf '| Host | %s |\n' "$(md_escape_table "$host")"
		printf '| Started | %s |\n' "$(md_escape_table "$START_TS")"
		printf '| Mode | %s |\n' "$(md_escape_table "$mode")"
		printf '| Safety | read-only checks; no secret contents printed |\n\n'

		printf '## Risk Overview\n\n'
		printf '| Severity | Count |\n'
		printf '|---|---:|\n'
		printf '| Critical | %s |\n' "$COUNTS_CRITICAL"
		printf '| High | %s |\n' "$COUNTS_HIGH"
		printf '| Medium | %s |\n' "$COUNTS_MEDIUM"
		printf '| Low | %s |\n' "$COUNTS_LOW"
		printf '| Info | %s |\n' "$COUNTS_INFO"
		printf '| Total | %s |\n\n' "$FINDING_COUNT"

		printf '## Top Actionable Findings\n\n'
		if [ -n "$TOP_FINDINGS_MD" ]; then
			printf '| ID | Severity | Confidence | Title | Evidence |\n'
			printf '|---:|---|---|---|---|\n'
			printf '%s\n' "$TOP_FINDINGS_MD"
		else
			printf 'No Critical, High, or Medium findings were detected by these non-invasive checks.\n\n'
		fi

		printf '## Detailed Findings\n\n'
		printf '%s' "$FINDINGS_MD"

		printf '## Final Summary\n\n'
		printf '| Severity | Count |\n'
		printf '|---|---:|\n'
		printf '| Critical | %s |\n' "$COUNTS_CRITICAL"
		printf '| High | %s |\n' "$COUNTS_HIGH"
		printf '| Medium | %s |\n' "$COUNTS_MEDIUM"
		printf '| Low | %s |\n' "$COUNTS_LOW"
		printf '| Info | %s |\n' "$COUNTS_INFO"
		printf '| Total | %s |\n' "$FINDING_COUNT"
	}
}

run_checks() {
	collect_system_info
	check_accounts_policy
	check_sudo
	check_sudoers_files
	check_doas_pkexec
	check_groups
	check_sensitive_permissions
	check_auth_policy_files
	check_path_risks
	check_home_permissions
	check_dynamic_linker
	check_pam_policy
	check_polkit
	check_kernel_hardening
	check_linux_security_modules
	check_suid_sgid
	check_capabilities
	check_interpreter_permissions
	check_world_writable
	check_cron
	check_systemd
	check_timers
	check_startup_persistence_paths
	check_logrotate_and_backup_jobs
	check_processes
	check_process_anomalies
	check_sessions_and_ipc
	check_environment
	check_history_indicators
	check_ssh
	check_ssh_key_permissions
	check_mounts_nfs
	check_containers
	check_firewall_network_posture
	check_security_tooling
	check_identity_integration
	check_local_credential_stores
	check_ci_cd_and_build_agents
	check_cloud_instance_metadata
	check_configs_exposure
	check_service_config_files
	check_network
	check_packages_kernel
	check_privileged_paths
	check_interesting_binaries
	check_acl_and_attributes
	check_active_write_validation
	check_active_tmp_execution
	check_active_path_hijack
	check_active_config_sibling_writes
	check_active_runtime_socket_access
}

main() {
	parse_args "$@"
	run_checks
	if [ "$JSON" -eq 1 ]; then
		report="$(build_json_report)"
	elif [ "$MARKDOWN" -eq 1 ]; then
		report="$(build_markdown_report)"
	else
		report="$(build_text_report)"
	fi
	if [ -n "$OUTFILE" ]; then
		printf '%s\n' "$report" > "$OUTFILE" || die "could not write report to $OUTFILE"
	fi
	printf '%s\n' "$report"
}

main "$@"
