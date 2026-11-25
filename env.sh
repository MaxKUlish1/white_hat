# source env.sh — инструменты white_hat в PATH (всё внутри папки проекта)
WH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$WH:$WH/tools/bin:$WH/tools/venv/bin:$WH/tools/testssl:$PATH"
export TRIVY_CACHE_DIR="$WH/tools/cache/trivy" GRYPE_DB_CACHE_DIR="$WH/tools/cache/grype" SEMGREP_SEND_METRICS=off
alias nuclei-safe='nuclei -etags dos,fuzz,intrusive -rl 10 -c 5'
