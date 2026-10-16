# go-nxs

A Go implementation of [NetherNet External Signaling](https://github.com/CloudburstMC/Network/blob/nethernet/docs/external-signaling/README.md)
(NXS) for hosts, built on [go-nethernet](https://github.com/df-mc/go-nethernet). NXS lets a
signaling provider such as [Warden](https://warden.cloud) handle HTTPS signaling with players,
while game traffic flows directly between players and the host.

The provider answers each player with a short-lived NXS1 token in the ICE ufrag. The host
validates the token from the player's first STUN request and admits the connection into a
`nethernet.Listener`, without seeing the player's SDP.

## Usage

`nxs.Provider` implements `nethernet.Signaling`:

```go
p, err := nxs.New(ctx, nxs.Config{
	Origin:   "https://provider.example",
	Token:    token,    // Optional: anonymous proof of work is used otherwise.
	StateDir: "nxs",    // One directory per instance. It holds secrets.
	Address:  ":19133", // The UDP port players connect to.
	Label:    "Lobby",  // Optional display name of a new registration.
	Software: &nxs.Software{Name: "MyServer", Version: "1.0.0"}, // Optional.
})
if err != nil {
	panic(err)
}
defer p.Close()

l, err := nethernet.ListenConfig{}.Listen(p)
```

The token decides whether the instance creates a service or attaches to an existing one.
Without a token, the provider can only create a service.

With gophertunnel, pass the Provider as `minecraft.NetherNet{Signaling: p}` to
`minecraft.ListenConfig.ListenNetwork`. After login, gophertunnel checks the login
identity against the admission through `nethernet.Conn.VerifyPublicKey`. See
[examples/gophertunnel](examples/gophertunnel).

The host advertises its local addresses and STUN mappings of `Address`, and withholds
public endpoints that fail the regional checks of the provider. Set `Config.Endpoints` if
players must reach it through a forwarded port instead.

### Options

- `WebSocket` carries operations over the WebSocket control transport of the provider,
  falling back to HTTPS.
- `AssistedJoins` lets the provider forward the offers of players over the WebSocket, for
  players that cannot be admitted statelessly.
- `Diagnostics` answers the connectivity checks of the provider on the gameplay socket.
  They never reach the Listener.
- `GameOutcomes` reports that the application calls `GameJoined` and `GameRejected`.
- `Location` declares where the host runs, as a country code, coordinates or both, with an
  optional city. Without it, the provider estimates the location from the connection.

```go
lat, lon := 40.71, -74.01
conf.Location = &nxs.Location{Country: "US", City: "New York", Latitude: &lat, Longitude: &lon}
```

`Pause` and `Resume` stop and resume admitting players without closing established
connections.

### Operator links

A provider may offer the operator a link, such as one that takes ownership of a new
service. The link returned with a new registration is logged. `RequestOperatorAction`
returns the latest link while it is valid, or a fresh one while the provider offers one:

```go
a, err := p.RequestOperatorAction(ctx)
if err != nil {
	return err
}
fmt.Println(a.Text, a.URL, "expires", a.ExpiresAt)
```

The link may carry a one-time credential. Show it to the operator, but never open, forward
or save it.

### Other operations

`RotateAdmissionKey`, `RotateMachineKey`, `Deregister` and `ExtensionRequest` expose
the remaining operations. Registrations are recovered in a new generation after a
restart, and an instance whose registration the provider no longer holds registers again
with a fresh machine key. If another process takes over the registration, the Provider
stops without reporting to the provider again, and its `Context` is canceled with
`ErrReplaced`, which also closes the listener.
