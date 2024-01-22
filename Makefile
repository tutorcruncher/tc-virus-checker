black = black -S -l 120
isort = isort -w 120

.PHONY: install
install:
	pip install -r requirements.txt

.PHONY: format
format:
	$(isort) src
	$(isort) tests
	$(black) src tests

.PHONY: lint
lint:
	flake8 src/ tests/
	$(isort) --check-only src
	$(isort) --check-only tests
	$(black) --check src tests

.PHONY: test
test:
	pytest --cov=src

.PHONY: build
build:
	docker build src/ -t src
