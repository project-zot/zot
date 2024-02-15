# Build scripts for images used in tests

## General instructions

This folder contains build files used to produce oci images used in zot tests.
Build them using stacker, and copy them over to ghrc.io using skopeo.

For example in case of the java image:

```bash
stacker build -f stacker-java.yaml
```

Check the image is scanned correctly using a trivy binary, in order to make sure it does
or does not contain expected vulnerabilities, in case the image is to be used for CVE scanning.

```bash
trivy image scan --input oci:java-test
```

Copy the new image over to ghcr.io using skopeo

```bash
skopeo copy --dest-creds=<user>:<token> oci:oci:java-test docker://ghcr.io/project-zot/test-images/java:0.0.1
```

## Images

### Java

The file stacker-java.yaml is used to produce the images in the repo at: ghcr.io/project-zot/test-images/java
Basically we compile a simple java file and without any vulnerabilities.
We can test the CVE scanning of Java images, including zot downloading the Java vulnerability DB.

### Spring

The file stacker-spring.yaml is used to produce the images in the repo at: ghcr.io/project-zot/test-images/spring-web
We just copy and download the already compiled spring jar file.
It can be scanned to identify at least one Java specific vulnerability in zot tests.
