FROM python:3.9-slim

WORKDIR /worker

COPY . .
RUN pip3 install --no-cache-dir -r requirements.txt

ARG FILES
ARG VERBOSE=0

ENTRYPOINT ["python", "remcos_exe_extractor.py"]
CMD ["-v", "$VERBOSE", "$FILES"]
