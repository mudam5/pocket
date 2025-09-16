FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY target/network-packet-analysis-0.1.0.jar /app/app.jar
EXPOSE 8080
CMD ["java","-jar","/app/app.jar"]