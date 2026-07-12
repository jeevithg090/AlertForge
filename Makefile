# SentinelForge — convenience targets
.PHONY: demo up down logs seed storm test

demo:   ## Build + start everything, wait for health, seed the demo
	./demo.sh

up:     ## Build + start the full stack and wait until healthy
	docker compose up -d --build --wait

down:   ## Stop the stack (add ARGS=-v to also wipe data volumes)
	docker compose down $(ARGS)

logs:   ## Tail backend + worker logs
	docker compose logs -f backend worker

seed:   ## Seed the hero brute-force incident
	python3 demo/seed_alerts.py --scenario brute_force

storm:  ## Seed a 30-alert storm (correlation/dedup demo)
	python3 demo/seed_alerts.py --storm 30

test:   ## Run backend unit tests
	cd backend && ./venv/bin/python -m pytest -q
