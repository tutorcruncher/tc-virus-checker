.PHONY: install
install:
	uv sync --dev

.PHONY: format
format:
	uv run ruff check . --fix
	uv run ruff format .

.PHONY: lint
lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run ty check .

.PHONY: test
test:
	uv run pytest --cov=src
