#!/bin/sh
set -eu

mkdir -p /app/data
if ! chown -R ipm:ipm /app/data 2>/dev/null; then
  echo "无法将 /app/data 设置为 ipm 用户可写，请检查数据卷权限" >&2
  exit 1
fi

CONFIG_SOURCE="${IPM_CONFIG_SOURCE:-/app/config.json}"
CONFIG_TARGET=/app/data/config.json
if [ -f "$CONFIG_SOURCE" ] && [ "$CONFIG_SOURCE" != "$CONFIG_TARGET" ]; then
  if [ ! -f "$CONFIG_TARGET" ] || [ "${IPM_CONFIG_FORCE:-}" = "1" ]; then
    cp "$CONFIG_SOURCE" "$CONFIG_TARGET"
    chown ipm:ipm "$CONFIG_TARGET"
    chmod 600 "$CONFIG_TARGET"
  fi
fi

exec su-exec ipm /app/icloud-privacy-mail "$@"
