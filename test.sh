#!/bin/sh

python3 manage.py runserver &
while ! nc -z localhost 8000; do sleep 0.1; done
echo "Starting up server"

set -e
curl --fail-with-body http://localhost:8000/profile/login
curl -X POST -F username=ta1 -F password=ta1 -c cj http://localhost:8000/profile/login
curl --fail-with-body -b cj http://localhost:8000/
curl --fail-with-body -b cj http://localhost:8000/1
curl --fail-with-body -b cj http://localhost:8000/1/grade
curl --fail-with-body -b cj http://localhost:8000/profile
    
