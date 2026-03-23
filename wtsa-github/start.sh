#!/usr/bin/env bash
# ═══════════════════════════════════════════════
# WTSA — Web Threat Scanning App
# Startup script
# ═══════════════════════════════════════════════

set -e

echo ""
echo "◈  WTSA — Web Threat Scanning App"
echo "───────────────────────────────────────────"

# 1. Check .env
if [ ! -f .env ]; then
  echo "⚠  .env not found — copying from .env.example"
  cp .env.example .env
  echo "   → Edit .env and add your ANTHROPIC_API_KEY and NOTION_API_KEY"
  echo "   → Then re-run this script"
  exit 1
fi

# 2. Install Python deps
echo "→ Installing Python dependencies..."
pip install -r requirements.txt -q

# 3. Install Playwright browsers
echo "→ Installing Playwright browsers..."
playwright install chromium

# 4. Start FastAPI backend
echo "→ Starting backend on http://localhost:8000"
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

echo ""
echo "✓  Backend running at http://localhost:8000"
echo "✓  API docs at     http://localhost:8000/docs"
echo ""
echo "   Load frontend/App.jsx in your Claude Artifact"
echo "   or open index.html in a React environment."
echo ""
echo "   Press Ctrl+C to stop."

# Trap to clean up on exit
trap "kill $BACKEND_PID 2>/dev/null; echo ''; echo 'Stopped.'" EXIT

wait $BACKEND_PID
