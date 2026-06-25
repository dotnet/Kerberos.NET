# Local KDC Sample

Shows how a **server application can host its own in-process KDC** instead of relying on
an off-box KDC (such as an Active Directory domain controller).

With [IAKERB](https://datatracker.ietf.org/doc/html/draft-ietf-kitten-iakerb), the client does
**not** contact a KDC directly. It tunnels its AS/TGS exchanges *through the target service* as
GSS-API tokens, and the service forwards them to a KDC on the client's behalf. In this sample that
KDC runs **in the same process** as the service, backed by a tiny local account store:

```
client (IAKerbInitiator)  -- GSS tokens -->  server (IAKerbAcceptor)
                                                   |
                                                   v
                                          in-proc KdcServer  <->  LocalSecurityStore
```

The client never opens a socket to a KDC; the server's in-proc `KdcServer` does all the work.

## Pieces

| File | Role |
| ---- | ---- |
| `LocalSecurityStore.cs` | In-memory account database (users, service, krbtgt) and key derivation. Replaces a "global" KDC/AD. |
| `LocalRealmService.cs` | Adapts the store to the KDC's `IRealmService` / `IPrincipalService` / `IKerberosPrincipal` interfaces. |
| `InProcessKdcTransport.cs` | A `KerberosTransport` that delivers KDC messages straight to `KdcServer.ProcessMessage` — no sockets. |
| `Program.cs` | Wires up the in-proc KDC, drives the `IAKerbInitiator` ⇄ `IAKerbAcceptor` handshake, and prints the authenticated identity. |

## Run

```
dotnet run --project Samples/LocalKdcSample
```

Expected output ends with:

```
Initiator state : Complete
Acceptor state  : Complete
Authenticated   : user@LOCALHOST.LOCAL
Service (SName) : host/appservice.localhost.local
```

## Key consistency

The same long-term secret must be reachable in two places, so the sample derives both from the
single `LocalSecurityStore`:

* the **KDC** uses it (via `IKerberosPrincipal.RetrieveLongTermCredential`) to encrypt the service ticket, and
* the **service** uses it (via the `KeyTable` from `GetServiceKeyTable`) to decrypt the final AP-REQ.
