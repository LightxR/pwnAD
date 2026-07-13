.PHONY: help install install-dev test test-unit test-integration test-all coverage lint format clean build css

help:
	@echo "pwnAD Development Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install          - Install pwnAD in production mode"
	@echo "  install-dev      - Install pwnAD with development dependencies"
	@echo "  test             - Run unit tests only"
	@echo "  test-unit        - Run unit tests with coverage"
	@echo "  test-integration - Run integration tests (requires AD lab)"
	@echo "  test-all         - Run all tests"
	@echo "  coverage         - Generate coverage report (HTML)"
	@echo "  lint             - Run all linters (flake8, black, isort, mypy)"
	@echo "  format           - Auto-format code with black and isort"
	@echo "  security         - Run security checks (bandit, safety)"
	@echo "  clean            - Remove build artifacts and cache files"
	@echo "  build            - Build distribution packages"
	@echo "  run-interactive  - Run pwnAD in interactive mode (example)"

install:
	pip install -e .

install-dev:
	pip install -e .
	pip install -r requirements-dev.txt

test: test-unit

test-unit:
	pytest tests/unit/ -v

test-integration:
	@echo "Running integration tests (requires AD lab)..."
	@echo "Make sure AD_LAB_AVAILABLE=1 is set"
	AD_LAB_AVAILABLE=1 pytest tests/integration/ -v

test-all:
	pytest tests/ -v

coverage:
	pytest tests/unit/ --cov=pwnAD --cov-report=html --cov-report=term-missing
	@echo ""
	@echo "Coverage report generated in htmlcov/index.html"

lint:
	@echo "Running flake8..."
	flake8 pwnAD/ --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 pwnAD/ --count --max-complexity=10 --max-line-length=127 --statistics
	@echo ""
	@echo "Checking code formatting with black..."
	black --check pwnAD/
	@echo ""
	@echo "Checking import sorting with isort..."
	isort --check-only pwnAD/
	@echo ""
	@echo "Running mypy type checker..."
	mypy pwnAD/ --ignore-missing-imports

format:
	@echo "Formatting code with black..."
	black pwnAD/
	@echo "Sorting imports with isort..."
	isort pwnAD/

security:
	@echo "Running bandit security linter..."
	bandit -r pwnAD/ -ll
	@echo ""
	@echo "Checking for known vulnerabilities..."
	safety check

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*.ccache' -delete
	@echo "Clean complete!"

css:
	npx tailwindcss -i pwnAD/web/static/src/input.css -o pwnAD/web/static/vendor/tailwind.min.css --minify

build: clean css
	python -m build

# Example usage targets
run-interactive:
	@echo "Running pwnAD in interactive mode..."
	@echo "Example: pwnAD -i --dc-ip 192.168.100.10 -d testlab.local -u testuser -p password"
	@echo "Modify this target with your test lab credentials"
