@echo off
REM Windows Makefile wrapper for AI-Driven WAF project
set TARGET=%1
if "%TARGET%"=="" goto help

if "%TARGET%"=="up" (
    echo [*] Starting docker compose services...
    docker compose up -d
    goto end
)

if "%TARGET%"=="down" (
    echo [*] Stopping docker compose services...
    docker compose down
    goto end
)

if "%TARGET%"=="demo-reset" (
    echo [*] Resetting demo state and seeding baseline traffic...
    python scripts/demo_reset.py
    goto end
)

if "%TARGET%"=="demo" (
    echo [*] Running attack simulator against WAF proxy...
    python demo/attack_simulator.py --target http://localhost:8080 --count 20
    goto end
)

if "%TARGET%"=="test" (
    echo [*] Running test suite...
    pytest -v
    goto end
)

if "%TARGET%"=="logs" (
    echo [*] Tailing logs from containers...
    docker compose logs -f
    goto end
)

if "%TARGET%"=="seed" (
    echo [*] Seeding demo database...
    python dashboard/api/seed_demo_data.py
    goto end
)

if "%TARGET%"=="clean" (
    echo [*] Cleaning containers and volumes...
    docker compose down -v
    goto end
)

:help
echo AI-Driven WAF - Windows Command Helper
echo Usage: make [command]
echo Available commands:
echo   make up          - Start all docker containers (Gateway, Dashboard, Juice Shop)
echo   make down        - Stop all docker containers
echo   make demo-reset  - Reset DB to clean seeded state (50 events)
echo   make demo        - Replay attack simulator (20 requests)
echo   make test        - Run python unit and contract tests
echo   make logs        - View live container logs
echo   make clean       - Remove containers and docker volumes

:end
