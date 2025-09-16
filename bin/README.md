# Network Packet Analysis (Java + PostgreSQL)
## Prereqs
- Java 17+
- Maven
- Docker (for Postgres) or a running Postgres instance

## Run Postgres
$ docker compose up -d

## Build
$ mvn clean package

## Run
Edit `src/main/resources/application.yml` to point to your Postgres host (if not local).
$ mvn spring-boot:run

Or build jar and run with Docker image (after mvn package):
$ docker build -t netanalysis:0.1 .
$ docker run --network host -e SPRING_PROFILES_ACTIVE=prod netanalysis:0.1

## Notes
- pcap4j requires native libpcap on the host; on Linux install `libpcap-dev`.
- Running live capture may require root privileges.