format: lint
	uv run -- ruff format

lint:
	uv run -- ruff check --fix
	uv run -- ty check

test:
	uv run -- pytest -v -n auto

install:
	uv sync --all-extras
	uv run -- prek install -f -t pre-commit -t pre-push

upgrade:
	uv sync --upgrade --all-extras

run:
	uv run main.py