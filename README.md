# Ballerina Web Services Security Library

[![Build](https://github.com/Nuvindu/module-wssecurity/actions/workflows/build-timestamped-master.yml/badge.svg)](https://github.com/Nuvindu/module-wssecurity/actions/workflows/build-timestamped-master.yml)
[![codecov](https://codecov.io/gh/Nuvindu/module-wssecurity/branch/main/graph/badge.svg)](https://codecov.io/gh/Nuvindu/module-wssecurity)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/Nuvindu/module-wssecurity.svg)](https://github.com/Nuvindu/module-wssecurity/commits/main)
[![Github issues](https://img.shields.io/github/issues/Nuvindu/module-wssecurity/module/pipe.svg?label=Open%20Issues)](https://github.com/Nuvindu/module-wssecurity/labels/module%2Fpipe)
[![GraalVM Check](https://github.com/Nuvindu/module-wssecurity/actions/workflows/build-with-bal-test-graalvm.yml/badge.svg)](https://github.com/Nuvindu/module-wssecurity/actions/workflows/build-with-bal-test-graalvm.yml)


This library offers a set of APIs designed to facilitate SOAP clients in incorporating web services security policies into their SOAP envelopes.

## Supported WS Security Policies

This library currently supports the following WS Security policies:

- **Username Token**: Provides authentication through username and password credentials.
- **Timestamp Token**: Enhances message integrity by incorporating timestamp information.
- **X509 Token**: Allows the use of X.509 certificates for secure communication.
- **Symmetric Binding**: Enables symmetric key-based security mechanisms.
- **Asymmetric Binding**: Facilitates the use of asymmetric cryptography for enhanced security.

These policies empower SOAP clients to enhance the security of their web service communications by selecting and implementing the appropriate security mechanisms to safeguard their SOAP envelopes.

## Build from the source

### Set up the prerequisites

1.  Download and install Java SE Development Kit (JDK) version 11 (from one of the following locations).

    - [Oracle](https://www.oracle.com/java/technologies/javase-jdk11-downloads.html)

    - [OpenJDK](https://adoptopenjdk.net/)

      > **Note:** Set the JAVA_HOME environment variable to the path name of the directory into which you installed JDK.

2.  Export your Github Personal access token with the read package permissions as follows.

              export packageUser=<Username>
              export packagePAT=<Personal access token>

### Build the source

Execute the commands below to build from the source.

1. To build the library:

   ```
   ./gradlew clean build
   ```

2. To run the integration tests:
   ```
   ./gradlew clean test
   ```
3. To build the module without the tests:
   ```
   ./gradlew clean build -x test
   ```
4. To debug module implementation:
   ```
   ./gradlew clean build -Pdebug=<port>
   ./gradlew clean test -Pdebug=<port>
   ```
5. To debug the module with Ballerina language:
   ```
   ./gradlew clean build -PbalJavaDebug=<port>
   ./gradlew clean test -PbalJavaDebug=<port>
   ```
6. Publish ZIP artifact to the local `.m2` repository:
   ```
   ./gradlew clean build publishToMavenLocal
   ```
7. Publish the generated artifacts to the local Ballerina central repository:
   ```
   ./gradlew clean build -PpublishToLocalCentral=true
   ```
8. Publish the generated artifacts to the Ballerina central repository:
   ```
   ./gradlew clean build -PpublishToCentral=true
   ```
