#!/bin/bash

echo "This is ENTRYPOINT.sh"

if [ -n "${GUNICORN_CMD_ARGS}" ]; then
    echo "GUNICORN_CMD_ARGS: ${GUNICORN_CMD_ARGS}"
fi

# Preloading before fork saves RAM, in addition to speeding up server boot.
GUNICORN_CMD_ARGS="${GUNICORN_CMD_ARGS} --preload"

echo "GUNICORN_CMD_ARGS: ${GUNICORN_CMD_ARGS}"

python manage.py migrate
# python manage.py collectstatic --no-input >/dev/null 2>&1
python manage.py createsuperuser --noinput --verbosity 3
# gunicorn --workers 1 --threads 8 --bind 0.0.0.0:${PORT} --enable-stdio-inheritance --capture-output --timeout 0 --preload init.wsgi:application
#exec gunicorn --bind "0.0.0.0:${PORT:-8000}" --forwarded-allow-ips '*' init.wsgi:application
python manage.py runserver 0.0.0.0:8000

