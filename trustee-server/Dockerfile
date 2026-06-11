FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY target/trustee-server-1.0-SNAPSHOT-fat.jar app.jar

ENV TRUSTEE_PORT=9090
ENV TRUSTEE_DB=/db/trustee.db
ENV TRUSTEE_CONFIG=/db/trustee-config.bin
ENV BULLETIN_BOARD_PATH=/bulletin/board.json
ENV CAS_URL=http://cas:8080

# Crear directorios de persistencia
RUN mkdir -p /db /bulletin

EXPOSE 9090

ENTRYPOINT ["java", "-jar", "app.jar"]
