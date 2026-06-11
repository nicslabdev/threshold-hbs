FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY target/dealer-cli-1.0-SNAPSHOT-fat.jar app.jar

ENV CAS_URL=http://cas:8080
ENV BULLETIN_BOARD_PATH=/bulletin/board.json
ENV SETUP_CONFIG_PATH=/config/setup-config.json
ENV TRUSTEE_URLS=trustee-0:9090,trustee-1:9090,trustee-2:9090

# Crear directorios
RUN mkdir -p /bulletin /config

ENTRYPOINT ["java", "-jar", "app.jar"]
