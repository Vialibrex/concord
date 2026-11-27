# Using Concord

## Building

Concord is built from source. The Rust toolchain is pinned in `rust-toolchain.toml` and installed by `rustup` on
first use. Run cargo from the repository root:

```sh
cargo build --release -p concord-desktop
```

The executable is written to `target/release/concord` (`concord.exe` on Windows). A release build uses link-time
optimisation and takes several minutes.

On Windows the build compiles BoringSSL from source and also needs:

- CMake, the MSVC build tools and LLVM (for `libclang`);
- NASM on x86_64;
- `clang-cl` and Ninja on ARM64.

Android's `libconcord.so` is built by the embedding application with the Android NDK.

## Running

```sh
concord run -c config.yaml
```

Concord loads the profile, opens the listeners it declares (`mixed-port`, `port`, `socks-port`, `redir-port`,
`tproxy-port`, `tun`, `listeners`, `tunnels`, `ss-config`, `vmess-config`) and logs to standard error at the profile's
`log-level`. Ctrl-C or SIGTERM stops it. `-f` is accepted for `-c`, as mihomo spells it.

TUN needs the privileges the platform requires to create a device and change routes.

### Running As A Server

A profile whose `listeners` declare protocol servers runs as a server with the same command; there is no separate
mode. A minimal Shadowsocks and VMess server:

```yaml
log-level: info
listeners:
  - name: ss-in
    type: shadowsocks
    port: 8388
    cipher: 2022-blake3-aes-128-gcm
    password: <base64 key of 16 bytes>
  - name: vmess-in
    type: vmess
    port: 10086
    certificate: certs/server.crt
    private-key: certs/server.key
    users:
      - username: alice
        uuid: <uuid>
rules:
  - MATCH,DIRECT
```

`listen` defaults to every address, as in mihomo, and `allow-lan` does not narrow a named listener. `certificate`
and `private-key` take inline PEM or a path inside the home directory; a path that leaves it or goes through a
symbolic link is refused, as provider paths are. Rules see each connection's listener as `IN-NAME` and its user as
`IN-USER`; a listener's `proxy` or `rule` sends its connections to that node or sub-rule. A port that cannot be bound
is logged and tried again on the next reload while the other ports serve. [compatibility.md](compatibility.md)
lists the types and options served.

The server is the `concord` executable built as in [Building](#building); no separate server package is released.
`-d` sets the home directory the certificate paths and provider files are read from, and SIGHUP reloads the profile
as below. Ports below 1024 need the privilege the platform asks for, `CAP_NET_BIND_SERVICE` on Linux.

### Checking A Profile

```sh
concord -t -c config.yaml
```

Loads the profile without running it and prints what applying it would warn about as JSON,
`{"warnings": [{"level", "code", "path", "message"}]}`, or `{"error": "..."}` with exit status 1 when it does not
load. `--android` checks it as the Android build loads it. While `mitm` is enabled, each of its lines that cannot be
read is skipped and reported (`mitm_line`, with the line of the profile); jq and cron expressions, scripts and the
files a line names are checked when the section is applied.

### Reloading

On macOS and Linux, SIGHUP reads the profile again. A profile that fails validation leaves the running configuration
in place, and the error is logged.

## The Home Directory

The home directory (`-d`, default `~/.config/concord`) holds:

- `config.yaml`, the working copy of the profile, which Concord replaces with the `-c` file on every start and
  reload. Edit the `-c` file, not this copy;
- provider caches;
- geodata.

### Geodata

`GEOIP` reads `Country.mmdb` (or `geoip.metadb`), `IP-ASN` reads `ASN.mmdb` and `GEOSITE` reads `GeoSite.dat` from
the home directory. A file that a rule needs and the directory lacks is downloaded from the profile's `geox-url`,
which defaults to the `MetaCubeX/meta-rules-dat` releases. Files placed there beforehand are used as they are.

## Dashboards

The profile's `external-controller` and `secret` serve the Clash REST API, so dashboards such as metacubexd, zashboard
and yacd connect as they do to other Clash cores. [compatibility.md](compatibility.md) lists the endpoints that differ.

## Embedding

An application can run Concord as a child process on desktop or load `libconcord.so` on Android, and drive it through
the JSON-RPC 2.0 API described in [`schema/api.json`](../schema/api.json): configuration, connections, traffic, logs
and DNS queries, with cancellation and live streams.
