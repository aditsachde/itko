# Itko Certificate Transparancy Log

Ikto is a new CT log that conforms to both the Sunlight and RFC6962 APIs, with a primary goal to be cheaper and easier to operate. RFC6962 monitoring APIs are implemented via a stateless proxy supported by some modifications to the base Sunlight spec.

## Design Decisions

### Sunlight Modifications

The changes to the Sunlight spec are the ones mentioned in [this email](https://groups.google.com/a/chromium.org/g/ct-policy/c/v9JzlbphYBs/m/8FQty5h0AAAJ).

The tile leaf structure has been modified to remove the PreCertExtraData, with the PrecertificateSigningCertificate being treated as just another intermediate. Instead, the SHA265 hashes for all of the intermediates that make up the chain are included in this structure to ensure that the original chain can always be reconstructed without much computatinal overhead. A prototype for this change can be found at [this commit](https://github.com/FiloSottile/sunlight/commit/dfd7d16682abd337d2b2c8b38263c92611e58cd0).

The modified struct is as follows:

```
struct {
    TimestampedEntry timestamped_entry;
    select(entry_type) {
        case x509_entry: Empty;
        case precert_entry: PreCertExtraData;
    } extra_data;
    Fingerprint chain<0..2^8-1>;
} TileLeaf;

struct {
    ASN.1Cert pre_certificate;
} PreCertExtraData;

opaque Fingerprint[32];
```

The `issuers.pem` bundle has also been removed, with the DER-encoded issuer certificates instead being served as individual files at `/issuers/{SHA256 fingerprint}` A prototype for this change can be found at [this commit](https://github.com/FiloSottile/sunlight/commit/f4e0843f0c91bd84b0457766cef4e478f0b2b009).

Lastly, the Sunlight log serves the Signed Tree Head as a [checkpoint](https://c2sp.org/tlog-checkpoint). However, in order to maintain compatibility with RFC6962, it uses the `TreeHeadSignature` as its signature algorithm, which ends up requiring extra wrangling with the existing `note` package and leaves the origin line of the checkpoint unauthenticated. Rather, a static JSON response matching RFC6962 Section 4.3 is written to `sth`.

### RFC6962 Compliance

The largest challenge with adapting Sunlight's tile-based monitoring API to RFC6962 is the difference that certificates are queried by hashes vs indicies. To solve this, there is an additional mapping API at `/hashes/<N>`.

This API is inspiried by k-anonymity model used by HaveIBeenPwned for the purposes of improving caching, rather than for privacy. Introducing a database to back this API undesirable, but so is storing a billion tiny files into S3, especially when compatibile alternatives may have minimum object sizes.

`<N>` is the first  `n` bits of the hash encoded as hexadecimal. The contents of this file contains an array with elements of the following structure: `Hash: 265-n bits, Index: 40 bits`. This array is sorted by the `hash` to allow for binary searching.

The value for `n` for the current log is served at `/hashes/mask`. The specific value for `n` can be calculated by taking the estimate for the number of certificates that will be submitted to the current shard and a target size for the individual files, then solving for a bitmask that will allow for the target to be met.

This API intended for use solely by the stateless proxy component, rather than other log monitors, and may change.

A nonfunctional example of what this could look like can be found at [this commit](https://github.com/FiloSottile/sunlight/commit/13a319871f929568d8ed09f84de7c00f5dfc0df2).

### Maximum Merge Delay Considerations

Enteries are incorporated into the log with zero merge delay. However, it is undesirable to clear the corresponding response on the `hashes` API from the cache with every new certificate submission. Instead, the cache TTL for these responses are set to just under 24 hours. As such, when using the `/v1/get-proof-by-hash` which requires using the `hashes` API, the log may appear to have a MMD of up to 24 hours. However, the true MMD is 0 and is reflected in all other endpoints. Logs using Itko should be submitted to Chrome and Safari as having a 24 hour MMD.

### High Availability

Itko implements high availability using a active-passive failover mechanism. Itko relies on Consul's session and distributed lockng mechanism to achieve this. Prior to initialization, an instance attempts to aquire a lock on the configured prefix, at `<prefix>/leader`. If it is locked, the instance will wait in this state until the lock is freed, at which point it will aquire the lock and initialize from scratch. 

In order to prevent misconfigurations, the configuration for the log is stored in Consul at `<prefix>/config`. This ensures that the configuration across all instances of a log is the same. Additionally, Consul supports CAS which can be used to implement Sunlight's checkpointing scheme.

Instead of Consul, really anything highly available could be used. Consul was chosen as it is familiar and running it in HA mode is straightforward. The load placed on this service is extremely low.

This scheme doesn't provide for 100% uptime, as during cutovers, there will be a couple seconds of downtime and requests in flight may be lost. This is ok as logs are only required to have 99% uptime over a three month period and CAs are equipped to handle and retry failed requests.

### Microservices?

Itko consists of two components, `itko-monitor` and `itko-submit`. The submission component handles the `/add-chain` and `/add-pre-chain` APIs. These is seperated out because they are stateful, require writing to S3, and require there to be only be one actively running instance per log, limiting the ability to scale out. The `itko-monitor` component is stateless and communicates only with S3. It implements all the other RFC6962 APIs which are necessary for monitoring the log for certificates. These APIs will see more load and seperating them out will also ensure that a flood of requests will not impact the submission apis. A future possibility is to compile the `itko-monitor` binary to WASM and run it on Fastly Compute, Cloudflare Workers, or similar.