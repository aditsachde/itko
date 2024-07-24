## Some Design Decsions

### Sunlight Modifications

Itko incorporates the updates to the Sunlight spec made as part of this PR: https://github.com/C2SP/C2SP/pull/76.

Additionally, the Sunlight log serves the Signed Tree Head as a [checkpoint](https://c2sp.org/tlog-checkpoint). This checkpoint uses the same signature algorithm as in RFC6962 but results in an unauthenticated origin line and requires a bunch of wrangling to convert back into a RFC6962 compliant response. Since Itko needs to implement RFC6962's `get-sth` endpoint, it stores the STH as a static JSON response at `/ct/v1/get-sth` instead of as a checkpoint at `/checkpoint`.

### RFC6962 Compliance

The largest challenge with adapting Sunlight's tile-based monitoring API to RFC6962 is the difference that certificates are queried by hashes vs indicies. To solve this, there is an additional mapping API at `/hashes/<N>`.

This API is inspiried by k-anonymity model used by HaveIBeenPwned for the purposes of improving caching, rather than for privacy. Introducing a database to back this API undesirable, but so is storing a billion tiny files into S3, especially when compatibile alternatives may have minimum object sizes.

`<N>` is the first `n` bits of the hash encoded as hexadecimal. The contents of this file contains an array with elements of the following structure: `Hash: 256 bits, Index: 40 bits`. This array is sorted by the `hash` to allow for binary searching.

The value for `n` for the current log is served at `/hashes/mask`. The specific value for `n` can be calculated by taking the estimate for the number of certificates that will be submitted to the current shard and a target size for the individual files, then solving for a bitmask that will allow for the target to be met.

A similar scheme is used for the dedupe cache, at `/dedupe/<N>`. The contents of this file contains an array with elements of the following structure: `Hash: 256 bits, Timestamp: 64 bits, Index: 40 bits`. This array is sorted by the `hash` to allow for binary searching. In this case, hash is the fingerprint of the leaf certificate.

This API intended for use solely by the stateless proxy component, rather than other log monitors, and may change.

### Maximum Merge Delay Considerations

Enteries are incorporated into the log with zero merge delay. However, it is undesirable to clear the corresponding response on the `hashes` API from the cache with every new certificate submission. Instead, the cache TTL for these responses are set to just under 24 hours. As such, when using the `/v1/get-proof-by-hash` which requires using the `hashes` API, the log may appear to have a MMD of up to 24 hours. However, the true MMD is 0 and is reflected in all other endpoints. Logs using Itko should be submitted to Chrome and Safari as having a 24 hour MMD.

### High Availability

Itko implements high availability using a active-passive failover mechanism. Itko relies on Consul's session and distributed lockng mechanism to achieve this. Prior to initialization, an instance attempts to aquire a lock on the configured prefix, at `<prefix>/leader`. If it is locked, the instance will wait in this state until the lock is freed, at which point it will aquire the lock and initialize from scratch.

In order to prevent misconfigurations, the configuration for the log is stored in Consul at `<prefix>/config`. This ensures that the configuration across all instances of a log is the same. Additionally, Consul supports CAS which can be used to implement Sunlight's checkpointing scheme.

Instead of Consul, really anything highly available could be used. Consul was chosen as it is familiar and running it in HA mode is straightforward. The load placed on this service is extremely low.

This scheme doesn't provide for 100% uptime, as during cutovers, there will be a couple seconds of downtime and requests in flight may be lost. This is ok as logs are only required to have 99% uptime over a three month period and CAs are equipped to handle and retry failed requests.

### Microservices?

Itko consists of two components, `itko-monitor` and `itko-submit`. The submission component handles the `/add-chain` and `/add-pre-chain` APIs. These is seperated out because they are stateful, require writing to S3, and require there to be only be one actively running instance per log, limiting the ability to scale out. The `itko-monitor` component is stateless and communicates only with S3. It implements all the other RFC6962 APIs which are necessary for monitoring the log for certificates. These APIs will see more load and seperating them out will also ensure that a flood of requests will not impact the submission apis. A future possibility is to compile the `itko-monitor` binary to WASM and run it on Fastly Compute, Cloudflare Workers, or similar.
