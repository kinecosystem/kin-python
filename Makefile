all: deps deps-dev coverage

.PHONY: deps
deps:
	pip install -r requirements.txt

.PHONY: deps-dev
deps-dev:
	pip install -r requirements.dev.txt

.PHONY: test
test:
	python -m pytest --timeout=5

.PHONY: coverage
coverage:
	python -m pytest --timeout=10 --cov=agora --cov-report term-missing tests .
