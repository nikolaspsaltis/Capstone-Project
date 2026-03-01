#!/usr/bin/env sh
set -eu

CODEX_ROOT="${CODEX_HOME:-$HOME/.codex}"
SESSIONS_DIR="$CODEX_ROOT/sessions"
OUT_DIR="${1:-$HOME/codex-backups}"
STAMP="$(date +%F-%H%M%S)"
ARCHIVE_PATH="$OUT_DIR/codex-chats-$STAMP.tar.gz"
MERGED_PATH="$OUT_DIR/all-codex-chats-$STAMP.jsonl"

if [ ! -d "$SESSIONS_DIR" ]; then
  echo "Error: sessions directory not found at $SESSIONS_DIR" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

# Compressed export preserving the sessions folder structure.
tar -czf "$ARCHIVE_PATH" -C "$CODEX_ROOT" sessions

# Flat export that concatenates all JSONL chat files in chronological path order.
tmp_list="$(mktemp)"
trap 'rm -f "$tmp_list"' EXIT INT TERM
find "$SESSIONS_DIR" -type f -name '*.jsonl' | sort > "$tmp_list"
> "$MERGED_PATH"
while IFS= read -r file_path; do
  cat "$file_path" >> "$MERGED_PATH"
done < "$tmp_list"

chat_file_count="$(wc -l < "$tmp_list" | tr -d ' ')"

echo "Export complete."
echo "Chat files: $chat_file_count"
echo "Archive: $ARCHIVE_PATH"
echo "Merged JSONL: $MERGED_PATH"
