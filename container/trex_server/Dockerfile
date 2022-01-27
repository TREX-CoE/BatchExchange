FROM almalinux:8

LABEL maintainer="NicoTippmann@MEGWARE"

ARG PORT

RUN yum update -y \
    && yum install -y python3 python3-pip\
    && yum clean -y all 

COPY ./webserver /home/webserver
WORKDIR /home/webserver

RUN pip3 install -r requirements.txt && python3 setup.py build

ENTRYPOINT ["/bin/sh", "-c", "gunicorn -w 4 -b 0.0.0.0:${PORT} 'batch_rest_server:create_app()'"]