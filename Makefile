# SentinelForge — convenience targets
.PHONY: help demo up dev down logs seed storm install test lint format eval frontend-check check

PY ?= backend/.venv/bin/python

help:   ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

demo:   ## Build + start everything, wait for health, seed the demo
	./demo.sh

up:     ## Build + start the full stack and wait until healthy
	docker compose up -d --build --wait

dev:    ## Start the stack with hot reload (source mounted)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

down:   ## Stop the stack (add ARGS=-v to also wipe data volumes)
	docker compose down $(ARGS)

logs:   ## Tail backend + worker logs
	docker compose logs -f backend worker

seed:   ## Seed the hero brute-force incident
	python3 demo/seed_alerts.py --scenario brute_force

storm:  ## Seed a 30-alert storm (correlation/dedup demo)
	python3 demo/seed_alerts.py --storm 30

install: ## Create backend/.venv and install backend + frontend dev dependencies
	cd backend && python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
	cd frontend && npm ci

test:   ## Run backend unit tests
	cd backend && ../$(PY) -m pytest -q

lint:   ## Lint backend (ruff) and frontend (eslint)
	cd backend && ../$(PY) -m ruff check . && ../$(PY) -m ruff format --check .
	cd frontend && npm run lint

format: ## Auto-format the backend
	cd backend && ../$(PY) -m ruff format . && ../$(PY) -m ruff check --fix .

eval:   ## Run the triage quality gate
	cd backend && ../$(PY) -m app.eval.harness

frontend-check: ## Typecheck + production build of the frontend
	cd frontend && npm run typecheck && npm run build

check: lint test eval frontend-check ## Everything CI runs
