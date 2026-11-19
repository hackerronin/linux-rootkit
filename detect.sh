#!/usr/bin/env bash

set -uo pipefail

R=$'\e[31m'; G=$'\e[32m'; B=$'\e[1m'; Z=$'\e[0m'
PASS=0; FAIL=0; HINT=""
ok() { PASS=$((PASS+1)); printf '  %s[ OK ]%s %s\n' "$G" "$Z" "$*"; }
no() { FAIL=$((FAIL+1)); printf '  %s[FAIL]%s %s\n' "$R" "$Z" "$*"; }
say(){ printf '\n%s== %s ==%s\n' "$B" "$*" "$Z"; }

K=$(uname -r); A=$(uname -m); BD=/lib/modules/$K/build
. /etc/os-release 2>/dev/null || true

printf '%s target: %s / %s / %s %s\n' "$B" "${PRETTY_NAME:-unknown}" "$K" "$A" "$Z"
[ "$(id -u)" -eq 0 ] && ok "running as root" || no "not root (sudo lagbe, naile symbol address 0 dekhabe)"

say "build prerequisites"
if [ -d "$BD" ] && [ -f "$BD/Makefile" ]; then
        ok "kernel headers: $BD"
else
        no "headers missing for $K"
        HINT="$HINT\n  apt-get install linux-headers-$K"
fi
grep -qs "$K" "$BD/include/generated/utsrelease.h" 2>/dev/null \
        && ok "headers match running kernel" || no "headers version != $K"
[ -f "$BD/Module.symvers" ] && ok "Module.symvers present" \
        || no "Module.symvers missing (no modversions data)"
for t in gcc make insmod rmmod; do
        command -v "$t" >/dev/null && ok "tool: $t" || { no "tool missing: $t"; HINT="$HINT\n  apt-get install build-essential kmod"; }
done

say "kernel config"
CFG=/boot/config-$K; [ -f "$CFG" ] || CFG=/lib/modules/$K/config
[ -f "$CFG" ] && ok "config: $CFG" || no "kernel config file not found"
for o in CONFIG_MODULES CONFIG_KPROBES CONFIG_KRETPROBES CONFIG_KALLSYMS CONFIG_MODULE_UNLOAD; do
        grep -qs "^$o=y" "$CFG" && ok "$o=y" || no "$o not =y"
done
grep -qs '^CONFIG_MODULE_SIG_FORCE=y' "$CFG" \
        && no "MODULE_SIG_FORCE=y (unsigned module refused)" || ok "MODULE_SIG_FORCE off"
grep -qs '^CONFIG_RANDSTRUCT=' "$CFG" \
        && no "RANDSTRUCT on (struct layout randomized)" || ok "RANDSTRUCT off"

say "runtime restrictions"
if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
        no "Secure Boot ENABLED (unsigned module blocked)"
else
        ok "Secure Boot off"
fi
if [ -r /sys/kernel/security/lockdown ] && \
   grep -q '\[integrity\]\|\[confidentiality\]' /sys/kernel/security/lockdown; then
        no "kernel lockdown active"
else
        ok "lockdown off"
fi
[ -r /sys/kernel/debug/kprobes/list ] && ok "kprobe runtime reachable" \
        || no "debugfs kprobe list unreachable"

say "hook symbols"
case "$A" in
        x86_64)  GD=__x64_sys_getdents64 ;;
        aarch64) GD=__arm64_sys_getdents64 ;;
        *)       GD=sys_getdents64 ;;
esac
for s in "$GD" seq_read_iter seq_read netlink_recvmsg; do
        addr=$(awk -v s="$s" '$3==s{print $1; exit}' /proc/kallsyms 2>/dev/null)
        if [ -n "$addr" ] && [ "$addr" != 0000000000000000 ]; then
                ok "$s @ $addr"
        else
                no "$s missing (renamed in this kernel, or kptr_restrict=1)"
        fi
done
awk '$3=="kallsyms_lookup_name"{f=1}END{exit !f}' /proc/kallsyms 2>/dev/null \
        && ok "kallsyms_lookup_name (taint clear only)" \
        || ok "kallsyms_lookup_name absent (hiding unaffected)"

say "result"
echo "  $PASS ok / $FAIL fail"
if [ "$FAIL" -eq 0 ]; then
        echo "  VERDICT: ready - ei kernel e module load hobe ar hook register korbe"
else
        echo "  VERDICT: upor er FAIL gulo age thik korte hobe"
        [ -n "$HINT" ] && printf "  install hint:%b\n" "$HINT"
fi
