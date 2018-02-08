FROM alpine

RUN apk update && apk add python3

RUN python3 -m pip install cherrypy

WORKDIR /ofs
COPY . ./

CMD ["python3", "flags.py", "the.flags"]
