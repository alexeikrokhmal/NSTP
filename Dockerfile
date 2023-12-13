FROM python:3

ADD NSTPv4.py /
ADD nstp_v4_pb2.py /
ADD testsConfiguration.yaml /tmp
ADD serverConfig.yaml /
RUN pip3 install protobuf
RUN pip3 install pynacl
RUN pip3 install passlib

ENTRYPOINT [ "python3.8", "-u", "./NSTPv4.py", "0.0.0.0", "22300" ]