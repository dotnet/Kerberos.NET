# Kerberos.NET
A complete Kerberos library built entirely in managed code without (many) OS dependencies.

[![Build Status](https://syfuhs2.visualstudio.com/Kerberos.NET/_apis/build/status/dotnet.Kerberos.NET?branchName=develop)](https://syfuhs2.visualstudio.com/Kerberos.NET/_build/latest?definitionId=5&branchName=develop)
[![Nuget Package](https://img.shields.io/nuget/v/Kerberos.NET.svg)](https://www.nuget.org/packages/Kerberos.NET)

### .NET Foundation

This project is supported by the [.NET Foundation](https://dotnetfoundation.org).

# What is it?

A library built in .NET that lets you operate on Kerberos messages. You can run a client, host your own KDC, or just validate incoming tickets. It's intended to be as lightweight as possible.

A [deep dive into the design of Kerberos.NET](https://syfuhs.net/a-deep-dive-into-the-design-kerberos-net) is available and worth a read.

# Fiddler Extension

You can find the Fiddler extension installer under [releases](https://github.com/dotnet/Kerberos.NET/releases) on the right hand side of this page. For more information go read [a write up on how to install and use it](https://syfuhs.net/a-fiddler-extension-for-kerberos-messages).

# Bruce Commmand Line Tool

The Bruce command line tool is a collection of utilities that let you interact with the Kerberos.NET library components and is available via `dotnet tool install bruce -g`. It includes useful tools for things like ticket cache and keytab management. It also includes the Ticket Decoder utility mentioned below. The tool more or less follows the MIT and Heimdal command line standards, but for more information on all  the tools in the suite type `help` from the Bruce command line.

![](docs/bruce.png?raw=true)

# Cross Platform Support

The library will work on all [supported .NET Standard 2.0 platforms with some caveats](https://syfuhs.net/cross-platform-support-for-kerberos).

# Getting Started
There are two ways you can go about using this library. The first is to download the code and build it locally. The second, better, option is to just use nuget.

```powershell
PM> Install-Package Kerberos.NET
```

## On Updates to the Nuget Packages

The nuget packages will generally be kept up to date with any changes to the core library.

# Using the Library

There are three ways you can use this library.

## Using The Kerberos Client

The client is intentionally simple as compared to clients found in other platforms. It's fully-featured and supports generating SPNego messages.

```C#
var client = new KerberosClient();

var kerbCred = new KerberosPasswordCredential("user@domain.com", "userP@ssw0rd!");

await client.Authenticate(kerbCred);

var ticket = await client.GetServiceTicket("host/appservice.corp.identityintervention.com");

var header = "Negotiate " + Convert.ToBase64String(ticket.EncodeGssApi().ToArray());
```
## Using the KDC Server

Hosting a KDC is a little more complicated as it requires listening on a particular port. Usually you listen on port 88.

```C#
var port = 88;

var options = new ListenerOptions
{
    ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
    DefaultRealm = "corp.identityintervention.com".ToUpper(),
    RealmLocator = realmName => new MyRealmService(realmName)
};

var listener = new KdcServiceListener(options);

await listener.Start();
```

The listener will wait until `listener.Stop()` is called (or disposed).

## Using the Authenticator

Ticket authentication occurs in two stages. The first stage validates the ticket for correctness via an `IKerberosValidator` with a default implementation of `KerberosValidator`. The second stage involves converting the ticket in to a usable `ClaimsIdentity` (a `KerberosIdentity : ClaimsIdentity` specifically), which occurs in the `KerberosAuthenticator`. 

The easiest way to get started is to create a new `KerberosAuthenticator` and calling `Authenticate`. If you need to tweak the behavior of the conversion, you can do so by overriding the `ConvertTicket(DecryptedData data)` method. 

```C#
var authenticator = new KerberosAuthenticator(new KeyTable(File.ReadAllBytes("sample.keytab")));

var identity = authenticator.Authenticate("YIIHCAYGKwYBBQUCoIIG...");

Assert.IsNotNull(identity);

var name = identity.Name;

Assert.IsFalse(string.IsNullOrWhitespace(name));
```

Note that the constructor parameter for the authenticator is a `KeyTable`. The `KeyTable` is a common format used to store keys on other platforms. You can either use a file created by a tool like `ktpass`, or you can just pass a `KerberosKey` during instantiation and it'll have the same effect.

# Kerberos Ticket Decoder Tool

This library comes with an optional utility to decode service tickets. It's easy to use. Just copy the Base64 encoded copy of the ticket into the left textbox. It will decode the unencrypted message if you don't provide a key. It will attempt to decrypt the message if you provide a key. You won't need to provide a host value if the ticket was encrypted using RC4, but it will need a host value if it's encrypted with AES (to derive the salt). Alternatively you could also include a keytab file if you happen to have that too.

![](docs/kerbDump.png?raw=true)

Here's a sample of what a sample ticket looks like:

```js
{
  "Request": {
    "KrbApReq": {
      "ProtocolVersionNumber": 5,
      "MessageType": "KRB_AP_REQ",
      "ApOptions": "Reserved",
      "Ticket": {
        "TicketNumber": 5,
        "Realm": "CORP.IDENTITYINTERVENTION.COM",
        "SName": {
          "FullyQualifiedName": "desktop-h71o9uu",
          "IsServiceName": false,
          "Type": "NT_PRINCIPAL",
          "Name": [
            "desktop-h71o9uu"
          ]
        },
        "EncryptedPart": {
          "EType": "AES256_CTS_HMAC_SHA1_96",
          "KeyVersionNumber": 3,
          "Cipher": "Vo4uodU2/OP1KvfvSXyZNZsflbXQFWQ8bbB6Xmb7aSJI2NilJQDVEz+jOXKh1H3UevlG0yJ/WsAAV+gF8aZ+ZqswjWoqP3Th0LjUR158y4ox2Yl+6AyVqCUtgQD2+pk3J4+n9P/UFj+2kji95xiR2myH1UpFid33xz+MLO83YeAVTlpYl2z8yPPCrTdg1l3JG4RGIB97Hq0txmcr8fDgrpSOeKPa1mx7sgJz/Eu703x+toqAztiHTQjd9DX+PflitG2H0cyUGz34He28YvQNvd1y32eIa0LtDMEE9PK4Wcb74bScGvjv3XTinCYAlWQpY+RUZn/AoR3A+s/T0dEqIaHRMeMWwnzouWA8QT6WSmatuXJx1mfXLNRBIa7QcRHJtKp9NPgseJLXFBdQ4G/ekzQOW4jC+zbWSuEbzQJOsmKcTg9f24aMSB+HRWS+bygWHdtzBcaiaTvFMsstn6BDXt4caAYJwC3HB2QT32ImNBWy+Mrm8r4DzxDi/qgW19cQwzuxWtqPZ+PnO/vnEQraG+8EeEi+Vge+IBWL1IMYgFu60l5mXeyu3mXRugqtJqGrKIqTmYvDTuit/v6TCnpw/BzaPakBm8kDT3oU13DNCQ6TMh/dgyVKZomn1SVxeBeGHpqEMfDShmLkLN8VLfjiC0w8CRdJZmfGH9slfte7J6JRN1qIVCibe8SoB3Y1QHEfF8CG8BAnjMB7A7v3d4DMieboFzkfh3liX6/HO44VdLsLwpsdlGZKDk2C61BS9DUZI6YqJ7K2M+kPrXIq7V/xVY6y53rZswQihaGWZNewUlB5hqEnERvu1GXJhRNj+zvTdWNraUjDC7dv+owjPsm4KZAKHU0+tjbX64LE6StrsFOQRfOE4X4zp2K9NjG8axGrEcYe2F+xM4i+wXdLct0CbdRtDSl4Qr/hSzEGsDehMYXlu7WUPGT2b8Ys2eBin7g6ezybL3qb0qLuH3gNS8J6YXn4gkVmCkJeAlPnmfcFsmk4TVJNeXTab7zobicdrjOosku7nbz13ZnYLkVnMC0kARP2tR7E3Zqf1cbAVYDhJm1CEjCnPKpuSA80AOv2m7qYPW06f0CJI7labGFrf2fLIhkvJqRit8B13DXaGpea/q+CrP3eXg1QBnhjEuoeJeEFO2+03ddxMv2GBXYYx5YKK+CqneUkj2WiwfkFdg6cBjY5GxllV3UxnJff4IKLMGIhtvmc/3WmeGm8W7XibtDIiUfbSa31rg/E+zY3RynYtEm/MoAwWjmAyLsyriO1jjHhWU469b1gflYbOPeDuFe8/KsV5YIB4GIYHTSfWB2Jfw+DH3soT92AV4S5J50Y3VgPrfI+cuNDbtfkjqxXALj+d6Lj4JK3qCoPlPTTtMm3lQkKiqLyTP8Kr4Tdo2gZ6ycWfIU9jdV1Fp3JouVdwGC6N7Xyq6rISSQg4SdCikZ1U5b4rWPS8MviFbcgSldh3PLITcvh3BS6uSQ7Jz5vvtME0tz5OcC30YLLRUNFBEkdsa+As69qihFNlUrWyQWCXa4FewRNRXBwjmsshgyjs+Vr+A=="
        }
      },
      "Authenticator": {
        "EType": "AES256_CTS_HMAC_SHA1_96",
        "KeyVersionNumber": null,
        "Cipher": "NnLmEFkmO3HXCSsJ0zoU+AF4BXPaSIKQ7dNwoL3peZ4fntxOVEt+3lFWUZgFbGx1cn1y1FLrPsSnwJ01yIu+9u9//RD3Srn1uD2lWjeVmnCDENd+hSoNeLdJoQFluY/MyYZx3KJWzGWa73PE+K+xOxCHWLGOZzI/EXnKm3xwN28Up8y3r31AJam3jANuJRdFMnDzj6Rvbt+FESsbH8dFAdB8rTmI28/+WRdnx3O69zPcrvw5hOcQLi40x63A6NbZ3TQNrG8xQr5aRC7mO69C17e4r7duawg9FHOHPMS4vdPFA2ShMAPuNRYQSSkskztk9yfjHQgCdfNmpPrGfIf4GVeg3RjZ0U87skHcmcKAqX7jtwoHbjQjOfgAtXnsBRhPU0a2nnfD53Fo8ZsONEUCkNAHWj2jYmyzL4WkDoqYKJhoA7YTiy+I2z/umhpXvao4E7NERCea7vPQv0TgtCxn6r5v936XWbBSt1CY4fSnjEgZfYYv0abhobC93Iktt2HCndXN7TceHAq5P3i8TZ6Cvd2HCVJ2/kyvzRWWtkPCFI1YRb3g379V1/VmIEOk+xEOup0YmNW5AicQVvvk"
      }
    },
    "KrbApRep": null
  },
  "Decrypted": {
    "Options": "Reserved",
    "EType": "AES256_CTS_HMAC_SHA1_96",
    "SName": {
      "FullyQualifiedName": "desktop-h71o9uu",
      "IsServiceName": false,
      "Type": "NT_PRINCIPAL",
      "Name": [
        "desktop-h71o9uu"
      ]
    },
    "Authenticator": {
      "AuthenticatorVersionNumber": 5,
      "Realm": "CORP.IDENTITYINTERVENTION.COM",
      "CName": {
        "FullyQualifiedName": "jack",
        "IsServiceName": false,
        "Type": "NT_PRINCIPAL",
        "Name": [
          "jack"
        ]
      },
      "Checksum": {
        "Type": "32771",
        "Checksum": "EAAAAAAAAAAAAAAAAAAAAAAAAAA8QAAA"
      },
      "CuSec": 305,
      "CTime": "2021-04-21T17:38:11+00:00",
      "Subkey": {
        "Usage": "Unknown",
        "EType": "AES256_CTS_HMAC_SHA1_96",
        "KeyValue": "nPIQrMQu/tpUV3dmeIJYjdUCnpg0sVDjFGHt8EK94EM="
      },
      "SequenceNumber": 404160760,
      "AuthorizationData": [
        {
          "Type": "AdIfRelevant",
          "Data": "MIHTMD+gBAICAI2hNwQ1MDMwMaADAgEAoSoEKAAAAAAAMAAATxr82+sI2kbFmPnkrjldLUfESt/oJzLaWWNqCkOgC7IwGqAEAgIAjqESBBAQF4PYQgIAAAkwwQQAAAAAMA6gBAICAI+hBgQEAEAAADBkoAQCAgCQoVwEWmQAZQBzAGsAdABvAHAALQBoADcAMQBvADkAdQB1AEAAQwBPAFIAUAAuAEkARABFAE4AVABJAFQAWQBJAE4AVABFAFIAVgBFAE4AVABJAE8ATgAuAEMATwBNAA=="
        }
      ]
    },
    "Ticket": {
      "Flags": [
        "EncryptedPreAuthentication",
        "PreAuthenticated",
        "Renewable",
        "Forwardable"
      ],
      "Key": {
        "Usage": "Unknown",
        "EType": "AES256_CTS_HMAC_SHA1_96",
        "KeyValue": "gXZ5AIsNAdQSo/qdEzkfw3RrLhhypyuG+YcZwqdX9mk="
      },
      "CRealm": "CORP.IDENTITYINTERVENTION.COM",
      "CName": {
        "FullyQualifiedName": "jack",
        "IsServiceName": false,
        "Type": "NT_PRINCIPAL",
        "Name": [
          "jack"
        ]
      },
      "Transited": {
        "Type": "DomainX500Compress",
        "Contents": ""
      },
      "AuthTime": "2021-04-21T17:24:53+00:00",
      "StartTime": "2021-04-21T17:38:11+00:00",
      "EndTime": "2021-04-22T03:24:53+00:00",
      "RenewTill": "2021-04-28T17:24:53+00:00",
      "CAddr": null,
      "AuthorizationData": [
        {
          "Type": "AdIfRelevant",
          "Data": "MIIDIjCCAx6gBAICAIChggMUBIIDEAUAAAAAAAAAAQAAAOgBAABYAAAAAAAAAAoAAAASAAAAQAIAAAAAAAAMAAAAmAAAAFgCAAAAAAAABgAAABAAAADwAgAAAAAAAAcAAAAQAAAAAAMAAAAAAAABEAgAzMzMzNgBAAAAAAAAAAACALv80z3TNtcB/////////3//////////fwrvbMLQ6tYBCq/W7Jnr1gH/////////fwgACAAEAAIAFgAWAAgAAgAAAAAADAACAAAAAAAQAAIAAAAAABQAAgAAAAAAGAACAGMAAABmBAAAAQIAAAYAAAAcAAIAIAAAAAAAAAAAAAAAAAAAAAAAAAAIAAoAIAACAAgACgAkAAIAKAACAAAAAAAAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAALAACAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAGoAYQBjAGsACwAAAAAAAAALAAAASgBhAGMAawAgAEgAYQBuAGQAZQB5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAGwEAAAHAAAAawQAAAcAAABoBAAABwAAAGoEAAAHAAAAAQIAAAcAAABpBAAABwAAAAUAAAAAAAAABAAAAEQAQwAwADEABQAAAAAAAAAEAAAAQwBPAFIAUAAEAAAAAQQAAAAAAAUVAAAAlAmTEqNsKELQwsZoAQAAADAAAgAHAAAAAQAAAAEBAAAAAAASAQAAAICglj3TNtcBCABqAGEAYwBrAAAAAAAAAEQAEAA6AFgAAAAAAAAAAABqAGEAYwBrAEAAYwBvAHIAcAAuAGkAZABlAG4AdABpAHQAeQBpAG4AdABlAHIAdgBlAG4AdABpAG8AbgAuAGMAbwBtAAAAAABDAE8AUgBQAC4ASQBEAEUATgBUAEkAVABZAEkATgBUAEUAUgBWAEUATgBUAEkATwBOAC4AQwBPAE0AAAAAAAAAEAAAAENIJ0ZsQaIecNA80hAAAAAdWyt6rmuoGI9Mcg0="
        },
        {
          "Type": "AdIfRelevant",
          "Data": "MF0wP6AEAgIAjaE3BDUwMzAxoAMCAQChKgQoAAAAAAAwAABPGvzb6wjaRsWY+eSuOV0tR8RK3+gnMtpZY2oKQ6ALsjAaoAQCAgCOoRIEEBAXg9hCAgAACTDBBAAAAAA="
        }
      ]
    },
    "DelegationTicket": null,
    "SessionKey": {
      "Usage": null,
      "EncryptionType": "AES256_CTS_HMAC_SHA1_96",
      "Host": null,
      "PrincipalName": null,
      "Version": null,
      "Salt": "",
      "Password": null,
      "IterationParameter": "",
      "PasswordBytes": "",
      "SaltFormat": "ActiveDirectoryService",
      "RequiresDerivation": false
    },
    "Skew": "00:05:00"
  },
  "Computed": {
    "Name": "jack@corp.identityintervention.com",
    "Restrictions": {
      "KerbAuthDataTokenRestrictions": [
        {
          "RestrictionType": 0,
          "Restriction": {
            "Flags": "Full",
            "TokenIntegrityLevel": "High",
            "MachineId": "Txr82+sI2kbFmPnkrjldLUfESt/oJzLaWWNqCkOgC7I="
          },
          "Type": "KerbAuthDataTokenRestrictions"
        },
        {
          "RestrictionType": 0,
          "Restriction": {
            "Flags": "Full",
            "TokenIntegrityLevel": "High",
            "MachineId": "Txr82+sI2kbFmPnkrjldLUfESt/oJzLaWWNqCkOgC7I="
          },
          "Type": "KerbAuthDataTokenRestrictions"
        }
      ],
      "KerbLocal": [
        {
          "Value": "EBeD2EICAAAJMMEEAAAAAA==",
          "Type": "KerbLocal"
        },
        {
          "Value": "EBeD2EICAAAJMMEEAAAAAA==",
          "Type": "KerbLocal"
        }
      ],
      "KerbApOptions": [
        {
          "Options": "ChannelBindingSupported",
          "Type": "KerbApOptions"
        }
      ],
      "KerbServiceTarget": [
        {
          "ServiceName": "desktop-h71o9uu@CORP.IDENTITYINTERVENTION.COM",
          "Type": "KerbServiceTarget"
        }
      ],
      "AdWin2kPac": [
        {
          "Mode": "Server",
          "DecodingErrors": [],
          "Version": 0,
          "LogonInfo": {
            "PacType": "LOGON_INFO",
            "LogonTime": "2021-04-21T17:24:53.4021307+00:00",
            "LogoffTime": "0001-01-01T00:00:00+00:00",
            "KickOffTime": "0001-01-01T00:00:00+00:00",
            "PwdLastChangeTime": "2021-01-14T23:55:39.0024458+00:00",
            "PwdCanChangeTime": "2021-01-15T23:55:39.0024458+00:00",
            "PwdMustChangeTime": "0001-01-01T00:00:00+00:00",
            "UserName": "jack",
            "UserDisplayName": "Jack Handey",
            "LogonScript": "",
            "ProfilePath": "",
            "HomeDirectory": "",
            "HomeDrive": "",
            "LogonCount": 99,
            "BadPasswordCount": 0,
            "UserId": 1126,
            "GroupId": 513,
            "GroupCount": 6,
            "GroupIds": [
              {
                "RelativeId": 1132,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              },
              {
                "RelativeId": 1131,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              },
              {
                "RelativeId": 1128,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              },
              {
                "RelativeId": 1130,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              },
              {
                "RelativeId": 513,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              },
              {
                "RelativeId": 1129,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              }
            ],
            "UserFlags": "LOGON_EXTRA_SIDS",
            "UserSessionKey": "AAAAAAAAAAAAAAAAAAAAAA==",
            "ServerName": "DC01\u0000",
            "DomainName": "CORP\u0000",
            "DomainId": "S-1-5-21-311626132-1109945507-1757856464",
            "Reserved1": "AAAAAAAAAAA=",
            "UserAccountControl": [
              "ADS_UF_LOCKOUT",
              "ADS_UF_NORMAL_ACCOUNT"
            ],
            "SubAuthStatus": 0,
            "LastSuccessfulILogon": "1601-01-01T00:00:00+00:00",
            "LastFailedILogon": "1601-01-01T00:00:00+00:00",
            "FailedILogonCount": 0,
            "Reserved3": 0,
            "ExtraSidCount": 1,
            "ExtraIds": [
              {
                "Sid": "S-1-18-1",
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ]
              }
            ],
            "ResourceDomainId": null,
            "ResourceGroupCount": 0,
            "ResourceGroupIds": null,
            "UserSid": {
              "Id": 1126,
              "Attributes": "0",
              "Value": "S-1-5-21-311626132-1109945507-1757856464-1126"
            },
            "GroupSid": {
              "Id": 513,
              "Attributes": "0",
              "Value": "S-1-5-21-311626132-1109945507-1757856464-513"
            },
            "GroupSids": [
              {
                "Id": 1132,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-1132"
              },
              {
                "Id": 1131,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-1131"
              },
              {
                "Id": 1128,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-1128"
              },
              {
                "Id": 1130,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-1130"
              },
              {
                "Id": 513,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-513"
              },
              {
                "Id": 1129,
                "Attributes": [
                  "SE_GROUP_MANDATORY",
                  "SE_GROUP_ENABLED_BY_DEFAULT",
                  "SE_GROUP_ENABLED"
                ],
                "Value": "S-1-5-21-311626132-1109945507-1757856464-1129"
              }
            ],
            "ExtraSids": [
              {
                "Id": 1,
                "Attributes": "0",
                "Value": "S-1-18-1"
              }
            ],
            "ResourceDomainSid": null,
            "ResourceGroups": [],
            "DomainSid": {
              "Id": 1757856464,
              "Attributes": "0",
              "Value": "S-1-5-21-311626132-1109945507-1757856464"
            }
          },
          "ServerSignature": {
            "Type": "HMAC_SHA1_96_AES256",
            "Signature": "Q0gnRmxBoh5w0DzS",
            "RODCIdentifier": 0,
            "PacType": "0"
          },
          "CredentialType": null,
          "KdcSignature": {
            "Type": "HMAC_SHA1_96_AES256",
            "Signature": "HVsreq5rqBiPTHIN",
            "RODCIdentifier": 0,
            "PacType": "0"
          },
          "ClientClaims": null,
          "DeviceClaims": null,
          "ClientInformation": {
            "ClientId": "2021-04-21T17:24:53+00:00",
            "Name": "jack",
            "PacType": "CLIENT_NAME_TICKET_INFO"
          },
          "UpnDomainInformation": {
            "Upn": "jack@corp.identityintervention.com",
            "Domain": "CORP.IDENTITYINTERVENTION.COM",
            "Flags": "0",
            "PacType": "UPN_DOMAIN_INFO"
          },
          "DelegationInformation": null,
          "HasRequiredFields": true,
          "Type": "AdWin2kPac"
        }
      ]
    },
    "ValidationMode": "Pac",
    "Claims": [
      {
        "Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1126"
      },
      {
        "Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "Value": "Jack Handey"
      },
      {
        "Type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "Value": "jack@corp.identityintervention.com"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1132"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1131"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1128"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1130"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-513"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "Value": "Domain Users"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-5-21-311626132-1109945507-1757856464-1129"
      },
      {
        "Type": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid",
        "Value": "S-1-18-1"
      }
    ]
  },
  "KeyTable": {
    "FileVersion": 2,
    "KerberosVersion": 5,
    "Entries": [
      {
        "EncryptionType": "NULL",
        "Length": 0,
        "Timestamp": "2021-04-21T23:52:22.5460123+00:00",
        "Version": 5,
        "Host": null,
        "PasswordBytes": "jBBI1KL19X3olbCK/f9p/+cxZi3RnqqQRH4WawB4EzY=",
        "KeyPrincipalName": {
          "Realm": "CORP.IDENTITYINTERVENTION.COM",
          "Names": [
            "STEVE-HOME"
          ],
          "NameType": "NT_SRV_HST",
          "FullyQualifiedName": "STEVE-HOME"
        },
        "Salt": null
      }
    ]
  }
}
```

## .NET Core

Hey, it works! Just add the nuget package as a reference and go. 

[More Information](http://syfuhs.net/2017/08/11/porting-kerberos-net-to-net-core/)

## Creating a Kerberos SPN in Active Directory

Active Directory requires an identity to be present that matches the domain where the token is being sent. This identity can be any user or computer object in Active Directory, but it needs to be configured correctly. This means it needs a Service Principal Name (SPN). You can find instructions on setting up a test user [here](https://syfuhs.net/2017/03/20/configuring-an-spn-in-active-directory-for-kerberos-net/).

## Active Directory Claims

Active Directory has supported claims since Server 2012. At the time you could only access the claims through Windows principals or ADFS dark magic. Kerberos.NET now natively supports parsing claims in kerberos tickets. Take a look at the [Claims Guide](http://syfuhs.net/2017/07/29/active-directory-claims-and-kerberos-net/) for more information on setting this up.

## KeyTable (keytab) File Generation

Kerberos.NET supports the KeyTable (keytab) file format for passing in the keys used to decrypt and validate Kerberos tickets. The keytab file format is a common format used by many platforms for storing keys. You can generate these files on Windows by using the `ktpass` command line utility, which is part of the Remote Server Administration Tools (RSAT) pack. You can install it on a *server* via PowerShell (or through the add Windows components dialog):

```powershell
Add-WindowsFeature RSAT
```

From there you can generate the keytab file by running the following command:

```bat
ktpass /princ HTTP/test.identityintervention.com@IDENTITIYINTERVENTION.COM /mapuser IDENTITYINTER\server01$ /pass P@ssw0rd! /out sample.keytab /crypto all /PTYPE KRB5_NT_SRV_INST /mapop set
```

The parameter `princ` is used to specify the generated PrincipalName, and `mapuser` which is used to map it to the user in Active Directory. The `crypto` parameter specifies which algorithms should generate entries.

## AES Support
AES tickets are supported natively. No need to do anything extra!

## Registering Custom Decryptors

You can add your own support for other algorithms like DES (don't know why you would, but...) where you associate an Encryption type to a Func<> that instantiates new decryptors. There's also nothing stopping you from DI'ing this process if you like.

```C#
KerberosRequest.RegisterDecryptor(
   EncryptionType.DES_CBC_MD5,
   (token) => new DESMD5DecryptedData(token)
);
```

# Replay Detection

The built-in replay detection uses a `MemoryCache` to temporarily store references to hashes of the ticket nonces. These references are removed when the ticket expires. The detection process occurs right after decryption as soon as the authenticator sequence number is available.

Note that the built-in detection logic does not work effectively when the application is clustered because the cache is not shared across machines. The built-in implementation uses an in-memory service and as such isn't shared with anyone.

You will need to create a cache that is shared across machines for this to work correctly in a clustered environment. This has been simplified greatly through the new .NET Core dependency injection services. All you need to do is register an `IDistributedCache` implementation. You can find more information on that in the [Mirosoft Docs](https://docs.microsoft.com/en-us/aspnet/core/performance/caching/distributed).

If you'd like to use your own replay detection just implement the `ITicketReplayValidator` interface and pass it in the `KerberosValidator` constructor.

# Samples!
There are samples!

 - [KerbCrypto](Samples/KerbCrypto) Runs through the 6 supported token formats.
    - rc4-kerberos-data
    - rc4-spnego-data
    - aes128-kerberos-data
    - aes128-spnego-data
    - aes256-kerberos-data
    - aes256-spnego-data
 - [KerbTester](Samples/KerbTester) A command line tool used to test real tickets and dump the parsed results.
 - [KerberosMiddlewareEndToEndSample](Samples/KerberosMiddlewareEndToEndSample) An end-to-end sample that shows how the server prompts for negotiation and the emulated browser's response.
 - [KerberosMiddlewareSample](Samples/KerberosMiddlewareSample) A simple pass/fail middleware sample that decodes a ticket if present, but otherwise never prompts to negotiate.
 - [KerberosWebSample](Samples/KerberosWebSample) A sample web project intended to be hosted in IIS that prompts to negotiate and validates any incoming tickets from the browser.

# License
This project has an MIT License. See the [License File](/LICENSE) for more details. Also see the [Notices file](/NOTICES) for more information on the licenses of projects this depends on.
