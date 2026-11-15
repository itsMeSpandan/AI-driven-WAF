.PHONY: help up down logs test lint demo openapi seed clean data train retrain-feedback promote-model rollback-model

help:
	@echo "AI-Driven WAF & Analytics Dashboard"
	@echo "Available commands:"
	@echo "  make up               - Start all docker-compose services"
	@echo "  make down             - Stop all docker-compose services"
	@echo "  make logs             - Tail logs from all docker containers"
	@echo "  make test             - Run python unit & contract tests across components"
	@echo "  make lint             - Run code quality linters (ruff / flake8 / black)"
	@echo "  make demo             - Run attack simulator against the running local demo app"
	@echo "  make openapi          - Export the OpenAPI JSON schema to docs/openapi.json"
	@echo "  make seed             - Seed the database with synthetic telemetry"
	@echo "  make data             - Download raw corpora and prepare processed splits"
	@echo "  make train            - Train and evaluate models, export model.joblib"
	@echo "  make retrain-feedback - Retrain candidate model on analyst feedback"
	@echo "  make promote-model    - Promote verified candidate model to active detector"
	@echo "  make rollback-model   - Roll back active detector to previous backup model"

data:
	python ml/data/download.py --dataset all
	python ml/prepare.py

train:
	python ml/train.py

retrain-feedback:
	python ml/retrain_feedback.py

promote-model:
	python ml/retrain_feedback.py --promote

rollback-model:
	python ml/retrain_feedback.py --rollback

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

test:
	pytest -v gateway/tests dashboard/api/tests ml/tests

benchmark:
	python eval/benchmark_latency.py

lint:
	python -m ruff check gateway dashboard ml demo || echo "Ruff check complete"

demo:
	python demo/attack_simulator.py --target http://localhost:8080 --count 20

openapi:
	python -c "import json; from dashboard.api.main import app; open('docs/openapi.json', 'w').write(json.dumps(app.openapi(), indent=2))"
	@echo "Exported docs/openapi.json successfully."

seed:
	python dashboard/api/seed_demo_data.py

clean:
	docker compose down -v
	rm -rf data/*.db __pycache__ .pytest_cache
