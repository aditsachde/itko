# Itko Certificate Transparancy Log

Ikto is a new CT log that conforms to both the [Static CT](https://c2sp.org/static-ct-api) and [RFC6962](https://datatracker.ietf.org/doc/html/rfc6962) APIs. RFC6962 monitoring APIs are implemented via a stateless proxy supported by some additions to the base Static CT spec.

## Public Instance

An operating instance using this log implementation can be found at `https://ct2025.itko.dev`.

| Config | Value |
| -- | -- |
| Log ID | `o6U+hSdTxD0uzfNlqqAKPwLqLggaBqzejSxyrPxX18E=` |
| Public Key | [`ct2025.itko.dev.public.der`](ct2025.itko.dev.public.der) |
| Start inclusive | `2025-01-01T00:00:00Z` |
| End exclusive | `2026-01-01T00:00:00Z` |
| Origin | `ct2025.itko.dev` |

## Motivation

The Static CT spec is based on innovations in the transparency ecosystem that make logs cheaper and easier to run. By serving static tiles and allowing clients to construct proofs themselves, running these logs becomes operationally simpler and significantly cheaper, as large databases are no longer required. Instead, these logs can be run directly on S3 or simple filesystems. This spec also unlocks the integration of CT into other efforts, such as [witnessing](https://github.com/transparency-dev/armored-witness/tree/main).

However, it is unclear how quickly this transition might take place. The Chrome and Apple CT programs have expressed some interest in transitioning to logs based on this new API, but the timeline for their support is unclear. Additionally, there is a significant number of existing CT log consumers that use the existing RFC6962 APIs. Itko exists to bridge the gap, allowing CT logs to integrate into witnessing efforts and making them cheaper to run, while still supporting the existing ecosystem to make the transition smoother.

## Operating

The two necessary binaries can be build as such

```
go build ./cmd/itko-submit
go build ./cmd/itko-monitor
```

The `submit` binary requires a local Consul agent running, as Consul is used to coordinate high avaliability. It takes a path to the Consul KV key used to store the config and an address to listen on for requests.

```
itko-submit -kv-path itkoalpha -listen-address localhost:3030
```

The `monitor` binary requires the configured mask size used for grouping the hash to index mappings and an address to listen on for requests. It also requires the address of the store for the tiles. This should be the address of bucket that the submit binary writes data to. In the following example, the address is set to a local minIO bucket.

```
itko-monitor -mask-size 5 -store-address 'http://localhost:9000/itkoalpha/' -listen-address 'localhost:3031'
```

## Design

Information about some high level design decisions can be found at [DESIGN.md](DESIGN.md)

## Acknowledgements

Itko would not have been possible without the transparency work done at Google, on [CT](https://github.com/google/certificate-transparency-go/) and [tile based logs](https://research.swtch.com/tlog), and Fillipo Valsorda's work on the [Sunlight log](https://sunlight.dev). Itko's implementation is largely based on the code and design decisions from Sunlight, and its testing infrastructure relies on that of certificate-transparency-go.
