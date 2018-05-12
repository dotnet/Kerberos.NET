# Kerberos.NET
A Managed Code validator for Kerberos tickets.

![Build Status](https://syfuhs2.visualstudio.com/_apis/public/build/definitions/bcf490cf-a965-4d26-999c-8de04067ee1e/1/badge)
[![Nuget Package](https://img.shields.io/nuget/v/Kerberos.NET.svg)](https://www.nuget.org/packages/Kerberos.NET)

# What is it?

Kerberos is a black box in the .NET world. It's services are exposed by Windows in a domain environment and most of the Kerberos-isms are hidden by Windows to simplify usage. .NET then tries to simplify further by treating Kerberos as just a Windows authentication method. This has the side effect that working with Kerberos at a protocol level in .NET is severely limited. That means doing anything out of the ordinary with Kerberos is either painful to do, or simply impossible.

The Point of Kerberos.NET is to make Kerberos much easier to work with in such scenarios. This is done by removing any hard dependencies on Windows and moving all ticket processing to the application itself. This of course means you don't need the application to be on a domain-joined machine, and it probably doesn't need to be on Windows either.

Take a look at the [Kerberos.NET](https://syfuhs.net/tag/kerberos-net/) tag for more information while the documentation here is updated.

# Getting Started
There are two ways you can go about using this library. The first is to download the code and build it locally. The second, better, option is to just use nuget.

```powershell
PM> Install-Package Kerberos.NET
```

This will install everything you need to validate tickets. Note that AES support has been merged into the main package because the bouncycastle dependency was removed!

## On Updates to the Nuget Packages

The nuget packages will be kept up to date with any changes to the core library. Check the package release notes for specific changes.

## Using the Library

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
AES tickets are now supported natively. No need to do anything extra!

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

 - [KerbCrypto](https://github.com/SteveSyfuhs/Kerberos.NET/tree/master/Samples/KerbCrypto) Runs through the 6 supported token formats.
    - rc4-kerberos-data
    - rc4-spnego-data
    - aes128-kerberos-data
    - aes128-spnego-data
    - aes256-kerberos-data
    - aes256-spnego-data
 - [KerbTester](https://github.com/SteveSyfuhs/Kerberos.NET/tree/master/Samples/KerbTester) A command line tool used to test real tickets and dump the parsed results.
 - [KerberosMiddlewareEndToEndSample](https://github.com/SteveSyfuhs/Kerberos.NET/tree/master/Samples/KerberosMiddlewareEndToEndSample) An end-to-end sample that shows how the server prompts for negotiation and the emulated browser's response.
 - [KerberosMiddlewareSample](https://github.com/SteveSyfuhs/Kerberos.NET/tree/master/Samples/KerberosMiddlewareEndToEndSample) A simple pass/fail middleware sample that decodes a ticket if present, but otherwise never prompts to negotiate.
 - [KerberosWebSample](https://github.com/SteveSyfuhs/Kerberos.NET/tree/master/Samples/KerberosWebSample) A sample web project intended to be hosted in IIS that prompts to negotiate and validates any incoming tickets from the browser.

# The TODO List
Just a list of things that should be done, but aren't yet.
 
 - The validation process should be vetted by someone other than the developer.
 - Samples for clustered environments should be created.
 - ~~Port to .NET Core~~ DONE!
 - ~~Support [keytab](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html) files~~ DONE!
 - ~~Replay detection is weak. The default `ITicketCacheValidator` needs to be a proper LMU cache so older entries are automatically cleaned up. The detection should also probably happen after a partial decoding so we can use the ticket's own expiry to remove itself from the cache. The validator should be simple enough that it can be backed by shared storage for clustered environments.~~ DONE!
 - ~~Validation and transformation isn't extensible. It just dumps a ClaimsIdentity with a fairly arbitrary list of claims from the ticket. You should be able to easily get whatever information you want out of the token. Validation also shouldn't be disabled so easily (it's currently just a bool flag on the validator class).~~ DONE!

# License
This project has an MIT License, but both the RC4 and MD4 implementations are externally sourced and have their own license.

The crypto data and key test files were sourced from https://github.com/drankye/haox/ originally under Apache 2.0 license https://github.com/drankye/haox/blob/master/LICENSE
