FROM python:3.10-slim

ENV APP_HOME=/app
ARG YOUR_ENV

ENV YOUR_ENV=${YOUR_ENV} \
  PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_VERSION=1.8.4

WORKDIR /app

RUN apt-get update
RUN apt-get install --yes --quiet --no-install-recommends build-essential
RUN pip install -U pip setuptools
RUN pip install poetry==$POETRY_VERSION

RUN poetry config virtualenvs.create false
COPY ./pyproject.toml pyproject.toml
COPY ./poetry.lock poetry.lock
RUN poetry install

COPY . .

EXPOSE 8000

RUN chmod +x ./entrypoint.sh
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ${APP_HOME}/entrypoint.sh
