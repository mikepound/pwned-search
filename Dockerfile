FROM python:3

RUN pip install requests

ADD . /app/pwned.py

ENTRYPOINT [ "python", "/app/pwned.py" ]
