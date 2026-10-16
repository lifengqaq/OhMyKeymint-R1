#!/system/bin/sh

# Refresh the module description shown in the root manager to reflect the
# runtime health of OhMyKeymint after boot. The description is one of two
# fixed states: the module started together with a reachable cloud endpoint,
# or it did not.

MODDIR=${0%/*}
STATE_DIR=/data/adb/omk

SUCCESS_TEXT='✅ OMK-R1已成功运行。本模块由浅笑呐二改自用。已成功连接云端。准备等着格你机机吧😄'
FAIL_TEXT='❌ OMK-R1 运行失败请把/data/misc/keystore/omk/logs/目录下日志给开发者。'

# Replace only the description line, preserving every other module.prop field.
set_description() {
  desc=$1
  prop="$MODDIR/module.prop"
  [ -f "$prop" ] || return 0

  tmp="$prop.tmp"
  if {
    grep -v '^description=' "$prop"
    printf 'description=%s\n' "$desc"
  } > "$tmp" 2>/dev/null; then
    cat "$tmp" > "$prop" 2>/dev/null && rm -f "$tmp"
  else
    rm -f "$tmp"
  fi
}

# A daemon is healthy only when its pidfile still points at the expected script.
daemon_alive() {
  pidfile=$1
  script=$2

  [ -f "$pidfile" ] || return 1
  pid=$(cat "$pidfile" 2>/dev/null)
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  [ -r "/proc/$pid/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -F "$script" >/dev/null 2>&1
}

find_module_keymint() {
  if [ -f "/data/adb/omk/keymint" ]; then
    echo /data/adb/omk/keymint
    return 0
  fi
  if [ -f "$MODDIR/keymint" ]; then
    echo "$MODDIR/keymint"
    return 0
  fi
  if [ -f "$MODDIR/libs/arm64-v8a/keymint" ]; then
    echo "$MODDIR/libs/arm64-v8a/keymint"
    return 0
  fi
  if [ -f "$MODDIR/libs/x86_64/keymint" ]; then
    echo "$MODDIR/libs/x86_64/keymint"
    return 0
  fi
  return 1
}

# Ask the module binary to confirm the configured cloud endpoint is reachable.
cloud_reachable() {
  bin=$(find_module_keymint)
  [ -n "$bin" ] || return 1

  export LD_LIBRARY_PATH="/apex/com.android.runtime/lib64:/apex/com.android.runtime/lib64/bionic:/system/lib64:/vendor/lib64:$LD_LIBRARY_PATH"
  out=$("$bin" --webui-check-cloud 2>/dev/null)
  [ "$out" = "ok" ]
}

# Wait until Android has finished booting before probing the runtime.
i=0
while [ "$i" -lt 120 ]; do
  [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && break
  sleep 5
  i=$((i + 1))
done
sleep 5

# The network may still be settling after boot; retry before declaring failure.
healthy=0
i=0
while [ "$i" -lt 6 ]; do
  if daemon_alive "$STATE_DIR/keymint-daemon.pid" "$MODDIR/daemon" \
    && daemon_alive "$STATE_DIR/injector-daemon.pid" "$MODDIR/daemon-injector" \
    && cloud_reachable; then
    healthy=1
    break
  fi
  sleep 10
  i=$((i + 1))
done

if [ "$healthy" = "1" ]; then
  set_description "$SUCCESS_TEXT"
else
  set_description "$FAIL_TEXT"
fi
