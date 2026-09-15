# Requests Chainer

Burp Suite extension to chain HTTP requests and reuse values extracted from previous responses.

The actual extension lives in [`chain-extension/`](chain-extension/), with its detailed README here:
[`chain-extension/README.md`](chain-extension/README.md).

```sh
cd chain-extension
./gradlew test jar
```

Generated JAR:

```text
chain-extension/build/libs/burp-request-chain.jar
```
