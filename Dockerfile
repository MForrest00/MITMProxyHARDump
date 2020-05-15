FROM python:3.7

RUN apt-get update -y

COPY requirements.txt /build/requirements.txt
COPY addon.py /build/app/addon.py
COPY archiver /build/app/archiver
COPY .mitmproxy /build/app/.mitmproxy

WORKDIR /build/app

EXPOSE 8080

RUN pip install -r ../requirements.txt

ENTRYPOINT [ "mitmdump", "-s", "addon.py", "--set", "confdir=./.mitmproxy" ]