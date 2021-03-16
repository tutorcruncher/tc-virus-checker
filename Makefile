black = black -S -l 120
isort = isort -w 120

.PHONY: install
install:
	pip install -r requirements.txt

.PHONY: format
format:
	$(isort) tc_av
	$(isort) tests
	$(black) tc_av tests

.PHONY: lint
lint:
	flake8 tc_av/ tests/
	$(isort) --check-only tc_av
	$(isort) --check-only tests
	$(black) --check tc_av tests

.PHONY: test
test:
	pytest --cov=tc_av

.PHONY: build
build:
	docker build tc_av/ -t tc_av
