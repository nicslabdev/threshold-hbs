FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copiar el fat JAR generado por maven-shade-plugin
COPY target/cas-1.0-SNAPSHOT-fat.jar app.jar

# Variables de entorno con valores por defecto
ENV CAS_PORT=8080
ENV CAS_DATA_DIR=/data

# Crear directorio de datos
RUN mkdir -p /data

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]