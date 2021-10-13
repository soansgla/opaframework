FROM openpolicyagent/opa:0.17.2

ADD config.yaml .

EXPOSE 80

CMD ["run", "-s", "-c", "config.yaml", "-a", ":80"]
