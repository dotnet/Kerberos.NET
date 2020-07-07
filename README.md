# Kerberos.NET
A complete Kerberos library built entirely in managed code without (many) OS dependencies.

[![Build Status](https://syfuhs2.visualstudio.com/Kerberos.NET/_apis/build/status/dotnet.Kerberos.NET?branchName=develop)](https://syfuhs2.visualstudio.com/Kerberos.NET/_build/latest?definitionId=5&branchName=develop)
[![Nuget Package](https://img.shields.io/nuget/v/Kerberos.NET.svg)](https://www.nuget.org/packages/Kerberos.NET)

### .NET Foundation

This project is supported by the [.NET Foundation](https://dotnetfoundation.org).

# What is it?

A library built in .NET that lets you operate on Kerberos messages. You can run a client, host your own KDC, or just validate incoming tickets. It's intended to be as lightweight as possible.

A [deep dive into the design of Kerberos.NET](https://syfuhs.net/a-deep-dive-into-the-design-kerberos-net) is available and worth a read.

# Cross Platform Support

The library will work on all [supported .NET Standard 2.0 platforms with some caveats](https://syfuhs.net/cross-platform-support-for-kerberos).

# Getting Started
There are two ways you can go about using this library. The first is to download the code and build it locally. The second, better, option is to just use nuget.

```powershell
PM> Install-Package Kerberos.NET
```

Note that the current Nuget package does not include the v3 build yet. This is to limit the impact to callers while it's in an Alpha state. There are also a handful of minor but breaking changes as it gets converted to .NET Standard 2.1 and removing the Framework build.

## On Updates to the Nuget Packages

The nuget packages will generally be kept up to date with any changes to the core library. Check the package release notes for specific changes. However as noted above the library has undergone a substantial overhaul and is in an alpha state.

# Using the Library

There are three ways you can use this library.

## Using The Kerberos Client

The client is intentionally simple and does not have all the features of a comprehensive client found in other platforms. This client is useful for lightweight testing and extending to meet your needs.

```C#
var client = new KerberosClient();

var kerbCred = new KerberosPasswordCredential("user@domain.com", "userP@ssw0rd!");

await client.Authenticate(kerbCred);

var ticket = await client.GetServiceTicket("host/appservice.corp.identityintervention.com");
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

Ticket authentication occurs in two stages. The first stage validates the ticket for correctness via an `IKerberosValidator` with a default implementation of `KerberosValidator`. The second stage involves converting the ticket in to a usable `ClaimsIdentity`, which occurs in the `KerberosAuthenticator`. 

The easiest way to get started is to create a new `KerberosAuthenticator` and calling `Authenticate`. If you need to tweak the behavior of the conversion, you can do so by overriding the `ConvertTicket(DecryptedData data)` method. 

```C#
var authenticator = new KerberosAuthenticator(new KeyTable(File.ReadAllBytes("sample.keytab")));

var identity = authenticator.Authenticate("YIIHCAYGKwYBBQUCoIIG...");

Assert.IsNotNull(identity);

var name = identity.Name;

Assert.IsFalse(string.IsNullOrWhitespace(name));
```

Note that the constructor parameter for the authenticator is a `KeyTable`. The `KeyTable` is a common format used to store keys on other platforms. You can either use a file created by a tool like `ktpass`, or you can just pass a `KerberosKey` during instantiation and it'll have the same effect.

# KerbDump Tool

This library comes with an optional utility to decode service tickets. It's easy to use. Just copy the Base64 encoded copy of the ticket into the left textbox. It will decode the unencrypted message if you don't provide a key. It will attempt to decrypt the message if you provide a key. You won't need to provide a host value if the ticket was encrypted using RC4, but it will need a host value if it's encrypted with AES (to derive the salt). Alternatively you could also include a keytab file if you happen to have that too.

![](kerbDump.png?raw=true)

Here's a sample of what a sample ticket looks like:

```js
{
  "Request": {
    "MechType": {
      "Mechanism": "SPNEGO",
      "Oid": "1.3.6.1.5.5.2"
    },
    "NegotiationRequest": {
      "MechToken": {
        "NegotiateExtension": null,
        "ThisMech": {
          "Mechanism": "Kerberos V5",
          "Oid": "1.2.840.113554.1.2.2"
        },
        "InnerContextToken": {
          "ProtocolVersionNumber": 5,
          "MessageType": [
            "KRB_AP_REQ"
          ],
          "APOptions": [
            "MUTUAL_REQUIRED"
          ],
          "Ticket": {
            "TicketVersionNumber": 5,
            "Realm": "CORP.IDENTITYINTERVENTION.COM",
            "SName": {
              "Realm": "CORP.IDENTITYINTERVENTION.COM",
              "NameType": [
                "NT_SRV_INST"
              ],
              "Names": [
                "host/delegated.identityintervention.com"
              ]
            },
            "EncPart": {
              "EType": [
                "RC4_HMAC_NT"
              ],
              "KeyVersionNumber": 3,
              "Cipher": "...snip..."
            }
          },
          "Authenticator": {
            "EType": [
              "RC4_HMAC_NT"
            ],
            "KeyVersionNumber": null,
            "Cipher": "...snip..."
          }
        },
        "NtlmNegotiate": null
      },
      "MechTypes": [
        {
          "Mechanism": "Kerberos V5 Legacy",
          "Oid": "1.2.840.48018.1.2.2"
        },
        {
          "Mechanism": "Kerberos V5",
          "Oid": "1.2.840.113554.1.2.2"
        },
        {
          "Mechanism": "NegoEx",
          "Oid": "1.3.6.1.4.1.311.2.2.30"
        },
        {
          "Mechanism": "NTLM",
          "Oid": "1.3.6.1.4.1.311.2.2.10"
        }
      ]
    },
    "Request": null
  },
  "Decrypted": {
    "EType": [
      "RC4_HMAC_NT"
    ],
    "Authenticator": {
      "VersionNumber": 5,
      "Realm": "CORP.IDENTITYINTERVENTION.COM",
      "CName": {
        "Realm": "CORP.IDENTITYINTERVENTION.COM",
        "NameType": [
          "NT_ENTERPRISE"
        ],
        "Names": [
          "tests4u"
        ]
      },
      "Checksum": "oAUCAwCAA6EaBBgQAAAAAAAAAAAAAAAAAAAAAAAAAD4AAAA=",
      "CuSec": 73,
      "CTime": "2019-02-23T03:26:00+00:00",
      "SubSessionKey": {
        "KeyType": [
          "RC4_HMAC_NT"
        ],
        "RawKey": "xG8Kpugq38doJ1I911iMCw=="
      },
      "SequenceNumber": 2122637123,
      "Subkey": "xG8Kpugq38doJ1I911iMCw==",
      "Authorizations": [
        {
          "Type": [
            "AdIfRelevant"
          ],
          "Authorizations": [
            {
              "Type": [
                "AD_ETYPE_NEGOTIATION"
              ],
              "ETypes": [
                [
                  "AES256_CTS_HMAC_SHA1_96"
                ],
                [
                  "AES128_CTS_HMAC_SHA1_96"
                ],
                [
                  "RC4_HMAC_NT"
                ]
              ]
            },
            {
              "RestrictionType": 0,
              "Restriction": {
                "Flags": [
                  "Full"
                ],
                "TokenIntegrityLevel": [
                  "Medium"
                ],
                "MachineId": "LkMHyrZTnvXuZfgAixO7o5JMZ1AXqiMsbEnsE2a2UsY="
              },
              "Type": [
                "KERB_AUTH_DATA_TOKEN_RESTRICTIONS"
              ]
            },
            {
              "Type": [
                "KERB_LOCAL"
              ],
              "Value": "EINby2wBAACoCPQAAAAAAA=="
            },
            {
              "Type": [
                "KERB_AP_OPTIONS"
              ],
              "Options": [
                "CHANNEL_BINDING_SUPPORTED"
              ]
            },
            {
              "Type": [
                "KERB_SERVICE_TARGET"
              ],
              "ServiceName": "host/delegated.identityintervention.com@CORP.IDENTITYINTERVENTION.COM"
            }
          ]
        }
      ]
    },
    "Ticket": {
      "TicketFlags": [
        "EncryptedPreAuthentication",
        "PreAuthenticated",
        "Renewable",
        "Forwardable"
      ],
      "Key": {
        "KeyType": [
          "RC4_HMAC_NT"
        ],
        "RawKey": "6ZBHsIubiNYuW/klY+IKhw=="
      },
      "CRealm": "CORP.IDENTITYINTERVENTION.COM",
      "CName": {
        "Realm": "CORP.IDENTITYINTERVENTION.COM",
        "NameType": [
          "NT_ENTERPRISE"
        ],
        "Names": [
          "tests4u"
        ]
      },
      "AuthTime": "2019-02-23T03:25:44+00:00",
      "StartTime": "2019-02-23T03:26:00+00:00",
      "EndTime": "2019-02-23T03:41:00+00:00",
      "RenewTill": "2019-03-02T03:25:44+00:00",
      "HostAddresses": 0,
      "AuthorizationData": [
        {
          "Type": [
            "AdIfRelevant"
          ],
          "Authorizations": [
            {
              "Type": [
                "AD_WIN2K_PAC"
              ],
              "Certificate": {
                "DecodingErrors": [],
                "Version": 0,
                "LogonInfo": {
                  "LogonTime": "1601-01-01T00:00:00+00:00",
                  "LogoffTime": "0001-01-01T00:00:00+00:00",
                  "KickOffTime": "0001-01-01T00:00:00+00:00",
                  "PwdLastChangeTime": "1601-01-01T00:05:11.1506395+00:00",
                  "PwdCanChangeTime": "1601-01-01T00:06:22.30801+00:00",
                  "PwdMustChangeTime": "1601-01-01T00:04:53.283094+00:00",
                  "LogonCount": 0,
                  "BadPasswordCount": 0,
                  "UserName": "tests4u",
                  "UserDisplayName": "Test S4U",
                  "LogonScript": "",
                  "ProfilePath": "",
                  "HomeDirectory": "",
                  "HomeDrive": "",
                  "ServerName": "DC01",
                  "DomainName": "corp",
                  "UserSid": {
                    "Attributes": [
                      "0"
                    ],
                    "Value": "S-1-5-21-1450222856-612051446-931472078-1107"
                  },
                  "GroupSid": {
                    "Attributes": [
                      "0"
                    ],
                    "Value": "S-1-5-21-1450222856-612051446-931472078-513"
                  },
                  "GroupSids": [
                    {
                      "Attributes": [
                        "SE_GROUP_MANDATORY",
                        "SE_GROUP_ENABLED_BY_DEFAULT",
                        "SE_GROUP_ENABLED"
                      ],
                      "Value": "S-1-5-21-1450222856-612051446-931472078-513"
                    }
                  ],
                  "ExtraSids": [
                    {
                      "Attributes": [
                        "SE_GROUP_MANDATORY",
                        "SE_GROUP_ENABLED_BY_DEFAULT",
                        "SE_GROUP_ENABLED"
                      ],
                      "Value": "S-1-18-2"
                    }
                  ],
                  "UserAccountControl": [
                    "ADS_UF_LOCKOUT",
                    "ADS_UF_MNS_LOGON_ACCOUNT"
                  ],
                  "UserFlags": [
                    "LOGON_EXTRA_SIDS"
                  ],
                  "FailedILogonCount": 0,
                  "LastFailedILogon": "1601-01-01T00:00:00+00:00",
                  "LastSuccessfulILogon": "1601-01-01T00:00:00+00:00",
                  "SubAuthStatus": 0,
                  "ResourceDomainSid": null,
                  "ResourceGroups": null,
                  "DomainSid": {
                    "Attributes": [
                      "0"
                    ],
                    "Value": "S-1-5-21-1450222856-612051446-931472078"
                  }
                },
                "ServerSignature": {
                  "Type": [
                    "KERB_CHECKSUM_HMAC_MD5"
                  ],
                  "Signature": "HeigjZh19Odn+5L76bHJwA==",
                  "RODCIdentifier": 0
                },
                "CredentialType": null,
                "KdcSignature": {
                  "Type": [
                    "HMAC_SHA1_96_AES256"
                  ],
                  "Signature": "G4Ph1DqTxZPuhlQo",
                  "RODCIdentifier": 0
                },
                "ClientClaims": null,
                "DeviceClaims": null,
                "ClientInformation": {
                  "ClientId": "1601-01-01T00:03:20.5972775+00:00",
                  "Name": "tests4u"
                },
                "UpnDomainInformation": {
                  "Upn": "tests4u@corp.identityintervention.com",
                  "Domain": "CORP.IDENTITYINTERVENTION.COM",
                  "Flags": [
                    "0"
                  ]
                },
                "DelegationInformation": {
                  "S4U2ProxyTarget": "host/delegated.identityintervention.com",
                  "S4UTransitedServices": [
                    "appsvc@CORP.IDENTITYINTERVENTION.COM"
                  ]
                }
              }
            }
          ]
        },
        {
          "Type": [
            "AdIfRelevant"
          ],
          "Authorizations": [
            {
              "RestrictionType": 0,
              "Restriction": {
                "Flags": [
                  "Full"
                ],
                "TokenIntegrityLevel": [
                  "Medium"
                ],
                "MachineId": "LkMHyrZTnvXuZfgAixO7o5JMZ1AXqiMsbEnsE2a2UsY="
              },
              "Type": [
                "KERB_AUTH_DATA_TOKEN_RESTRICTIONS"
              ]
            },
            {
              "Type": [
                "KERB_LOCAL"
              ],
              "Value": "EINby2wBAACYCPQAAAAAAA=="
            }
          ]
        }
      ],
      "EncryptionKey": "6ZBHsIubiNYuW/klY+IKhw==",
      "Transited": [
        {
          "Type": [
            "DomainX500Compress"
          ],
          "Contents": ""
        }
      ]
    },
    "Skew": "00:05:00"
  },
  "KeyTable": {
    "FileVersion": 2,
    "KerberosVersion": 5,
    "Entries": [
      {
        "EncryptionType": null,
        "Length": 0,
        "Timestamp": "0001-01-01T00:00:00+00:00",
        "Version": 0,
        "Host": null,
        "PasswordBytes": "UABAAHMAcwB3ADAAcgBkACEA",
        "Key": null
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
