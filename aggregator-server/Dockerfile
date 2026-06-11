FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY target/aggregator-server-1.0-SNAPSHOT-fat.jar app.jar

ENV AGGREGATOR_PORT=8081
ENV CAS_URL=http://cas:8080
ENV BULLETIN_BOARD_PATH=/bulletin/board.json
ENV TRUSTEE_URLS=trustee-0:9090,trustee-1:9090,trustee-2:9090

# Crear directorio para el bulletin board
RUN mkdir -p /bulletin

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]
