.PHONY: install run lint format typecheck build clean

install:
	pip install -r requirements.txt

run:
	python main.py

lint:
	ruff check .

format:
	black .
	ruff check . --fix

typecheck:
	mypy .

build:
	pyinstaller --name pcap-traffic-studio --windowed main.py

clean:
	rm -rf build dist __pycache__ .mypy_cache .ruff_cache
