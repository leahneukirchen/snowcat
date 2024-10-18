# snowcat: encrypted data streams over sockets

snowcat is an encrypting proxy for bidirectional data streams using
the Noise Protocol Framework.

snowcat is possibly an alternative to SSH port forwarding, stunnel,
spiped, or WireProxy.

## Caution

**snowcat is based on the time-proven Go crypto ecosystem, but the
tool itself has not been audited.  Use at your own risk.**

## Usage

Unauthenticated TCP proxy server (not recommended):

	remote% snowcat snow::7777 localhost:5432
    local% snowcat localhost:5432 snow:remote.host.example.org:7777

Use with client authentication:

	local% snowcat genkey >key.sec
    local% snowcat pubkey <key.sec
    S0zYgy94/tR+uIoKhV3grFh9qYdz2WruqSRpgUGBd0U=
    remote% snowcat snow::7777,verify=S0zYgy94/tR+uIoKhV3grFh9qYdz2WruqSRpgUGBd0U= localhost:5432
    local% snowcat localhost:5432 snow:remote.host.example.org:7777,privkey=$PWD/key.sec

Use `privkey=...,verify=...` on both sides to ensure mutual authentication.

snowcat uses the Noise pattern XX to allow for configurable
client/server verification.  Unless specified explicitly, random
static keys are used.

## Protocol

Until the 1.0 release, only using the same code version on both peers is supported.

## Yet missing features

No promises, but features added likely in the future:

- Pre-shared keys
- inetd mode
- Dispatching to different services based on key
- Certificate support (Ed25519)

## License

snowcat is released under the MIT License.
