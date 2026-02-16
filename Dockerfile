FROM quay.io/keycloak/keycloak:26.5.3

#COPY target/lib/*.jar ./providers/
COPY spi/target/keycloak-spi-trusted-device-*-SNAPSHOT.jar /opt/keycloak/providers/keycloak-spi-trusted-device.jar
