ARG PYTHON_VERSION=3.6

FROM python:${PYTHON_VERSION}-buster

# Update python build dependencies
RUN python3 -m pip install -U pip setuptools wheel

# Download poetry
ADD 'https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py' /src/get-poetry.py

# Install poetry
RUN env POETRY_HOME=/opt/poetry python /src/get-poetry.py

ENTRYPOINT env MAKEFLAGS=$(nproc) /opt/poetry/bin/poetry
