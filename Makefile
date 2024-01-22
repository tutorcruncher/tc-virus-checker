black = black -S -l 120
isort = isort -w 120

.PHONY: install
install:
	pip install -r requirements.txt

.PHONY: install-test
install-test: install
	pip install -r tests/requirements.txt

.PHONY: lint
lint:
	ruff check src/ tests/
	ruff format src/ tests/ --check

.PHONY: format
format:
	ruff check src/ tests/ --fix
	ruff format src/ tests/

.PHONY: test
test:
	pytest --cov=src

.PHONY: build
build:
	docker build src/ -t src
