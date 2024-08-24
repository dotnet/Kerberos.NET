// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class NdrTests : BaseTest
    {
        private const string S4UProxyTicket = "boIF3zCCBdugAwIBBaEDAgEOogcDBQAgAAAAo4IFEGGCBQwwggUIoAMCAQWhHxsdQ09SUC5JREVOVElUWUlOVEVSVkVOVElPTi5DT02iGDAWoAMC" +
            "AQOhDzANGwRob3N0GwVkb3duMqOCBMQwggTAoAMCARehAwIBAqKCBLIEggSuLAxrwUFytLsDOwttiF/jwzkkbMeWkExGskLBYsvZdIBkW0LxtO4DaUURhfc0MOo2xLN7RdrWZthmAcZmyhHtas" +
            "rWH/Y0ZhpA53pnV9XibrvlMyrCT9xx8PitMIIwOVTvZnMG+sH6BcwbmXtQ+zfst6wrmKJcKtMn7gNEkW75v0CMFN6k6w7jZVuJBJNHsfIANgNBhsiS50wNsgtMCdqp11qWK582gNdWq2dCfFVE" +
            "HgCxV2cWK+jNJTR7wMlq/ov4au4udZaLVcbVB+QKbLbqWcwwKcNVqAeTsCatWXPxEprvGNjyiG+bz+MzHiNsqQYsLU5Kp7MxjPF3PYVVdSkp9eJKNsWFMkgTzEDFvAYIwRDKMzs7YxmVvklTt7" +
            "KUCLE3VYakRaFCCs5nQZ+ReXtZQHEAMCKnYJaLjeAvpeMINcpykINkocDMOn328UK56GGrYN7v2AEYdeo1PEmv5DLOQXcKHIoKbwY2VtI+yPFR/y9kit1pHsZMrhvDvCaQZxTunQFBO6EkX/86" +
            "MLJXNnPuo7byTHVJvc3BaGPQ7KXWXMBkgbVnT+dStjR9M7M+Pxtgn0rfPEg1S6l7fx5atoWVQLuZ9kJzpMPo5A5mKyrnMz6o8XRtcibBd7Jn00LrZc64ZAWDvipR5MRAWOEimcPZWMZWp+AM3Q" +
            "rR4uRCbi4ACIEf1cStUDh1AiFrBm7k18NFI3U5fKK8XOCKCwraflnGaZn7GCZSiQzB5gJHEpdJULnNtXWeGy9AUYQVqWFN0gnX3vUYW/lZKDmJZrEjcmS4/X/I+At6HF1GFQJ353iYFXfbSxx1" +
            "Nit3ADAzlndH5EmBN+stmJLH6LlPY6tVzOWwjLhGscFtndIPGZPQppOOn5WHhBz7zWE7B0d1owYD0e6s2J2lUcoYcsuOtKpPRUXLfLthnorCs+wucaCujAVydAMzXNWkOHA9iIlZTMwGQGpjwN" +
            "Q1iJ8z12hgMefpC1QGWcNMButfZaTW461lSAWL70diYIps8Z993AZ2Gx+Mlnr3OXebpFenqTCoicakNZ6FpKBcYF+DCJ6k69ZE5HAYxIdmqM4LtfEhfrHGfK56KDTAKqhubm+RPgDNdzFz5m+Y" +
            "yOLN29/oAFBMlXtMUq3lBwOmbt+Eg/LlkbKBIgbNXhCaIPqi+RJdU7hDkJEP17ZUbFWCjxVHWOg3rcW0+Hm31MEq9iteGHGkTjiRpG8Ob+9xWWUaJ6Cj7RJp6Td3CXNf7h9UxDXVpJc9Sd1c+q" +
            "7Y/4KfWq7MqQEcYEi7Q5lKHPGf+rZlOUdi+59g0MVGW2SrpIWV8XWvtZsS9fEcEnG0hhlUr/rFMq4kIZhdBun5VJlZqOv5Ptirzn9xn/0g98pUltRQXnIi1r2O2hglWySOifIfX+gzH98+9310" +
            "Y1B5B/iEXp4hwNTsUiozw+CwTu78f+mpV2HBx31cV5VIScdZrqgYa3D51+CaBYsLSOe5gZkMBme+eNHzIRW95OCkpsY1K7F4nuNO0pwO73GvX22eliqOEuVPa1/82fgyD9y0rXjNwHbTHRrmef" +
            "QpXsMxbf8OTdTpPUjM+YO15nLKpyU1OkLkPG2OotRgIp0NoeKcyaSBsTCBrqADAgEXooGmBIGj24IhfgqoJAvOcADQ4hEiN9rrnB1iG43jBJqvsZlPtiy60LMNDKQEiQrW5yNca11V8ZJP0iPG" +
            "xEmequOqPQvcSAk4I3EpzYH7wcdvBN/Cie0xUC6nrLJAoO1sScn7iiR2xKwBwOLWSvJzUa5XZ7OlelLQjYCp2r3+I6TMPf8OUEvuhzSfKm5rBiHpR9owA83+RsGtXTAQsFZ8bghEsO8Q9QRq9A==";


        [TestMethod]
        public void NdrClientClaimsEncoding()
        {
            byte[] encodedClientClaims =
               {0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x02, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xe8, 0x00, 0x00, 0x00, 0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xd8, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x0c, 0x00, 0x02, 0x00, 0x03, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x31, 0x00, 0x32, 0x00,
                0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x37, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x65, 0x00, 0x79, 0x00, 0x4a, 0x00, 0x30, 0x00,
                0x65, 0x00, 0x58, 0x00, 0x41, 0x00, 0x69, 0x00, 0x4f, 0x00, 0x69, 0x00, 0x4a, 0x00, 0x4b, 0x00,
                0x56, 0x00, 0x31, 0x00, 0x51, 0x00, 0x69, 0x00, 0x4c, 0x00, 0x43, 0x00, 0x4a, 0x00, 0x68, 0x00,
                0x62, 0x00, 0x47, 0x00, 0x63, 0x00, 0x69, 0x00, 0x4f, 0x00, 0x69, 0x00, 0x4a, 0x00, 0x53, 0x00,
                0x55, 0x00, 0x7a, 0x00, 0x49, 0x00, 0x31, 0x00, 0x4e, 0x00, 0x69, 0x00, 0x49, 0x00, 0x73, 0x00,
                0x49, 0x00, 0x6e, 0x00, 0x67, 0x00, 0x31, 0x00, 0x64, 0x00, 0x43, 0x00, 0x49, 0x00, 0x36, 0x00,
                0x49, 0x00, 0x6b, 0x00, 0x31, 0x00, 0x48, 0x00, 0x54, 0x00, 0x48, 0x00, 0x46, 0x00, 0x71, 0x00,
                0x4f, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            ClaimEntry entry = new ClaimEntry
            {
                Id = "123",
                Type = ClaimType.CLAIM_TYPE_STRING,
                Values = new List<object> { "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1HTHFqOT" }
            };

            entry.Count = entry.Values.Count;

            ClaimsArray array = new ClaimsArray
            {
                ClaimSource = ClaimSourceType.CLAIMS_SOURCE_TYPE_AD,
                ClaimEntries = new List<ClaimEntry> { entry },
                Count = 1
            };

            ClaimsSet claims = new ClaimsSet
            {
                ReservedType = 0,
                ClaimsArray = new List<ClaimsArray> { array },
                ReservedField = ReadOnlyMemory<byte>.Empty,
                Count = 1,
                ReservedFieldSize = 0
            };

            ClaimsSetMetadata ClientClaims = new ClaimsSetMetadata
            {
                ClaimsSet = claims,
                CompressionFormat = CompressionFormat.COMPRESSION_FORMAT_NONE,
                ReservedType = 0,
                ReservedField = ReadOnlyMemory<byte>.Empty,
                ReservedFieldSize = 0
            };

            var encoded = ClientClaims.Marshal();

            Assert.IsTrue(encoded.Span.SequenceEqual(encodedClientClaims));
        }

        private static async Task<PrivilegedAttributeCertificate> GeneratePac(bool includeClaims)
        {
            DecryptedKrbApReq result = null;

            if (includeClaims)
            {
                result = await GeneratePacContainingClaims();
            }
            else
            {
                result = await GeneratePacWithoutClaims();
            }

            var pacData = result.Ticket.AuthorizationData
                .Where(d => d.Type == AuthorizationDataType.AdIfRelevant)
                .Select(d => d.DecodeAdIfRelevant()
                    .Where(a => a.Type == AuthorizationDataType.AdWin2kPac)
                ).First();

            var pac = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = pacData.First().Data });

            Assert.AreEqual(0, pac.DecodingErrors.Count());

            return pac;
        }

        private static async Task<DecryptedKrbApReq> GeneratePacContainingClaims()
        {
            var validator = new KerberosValidator(new KerberosKey("P@ssw0rd!")) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(Convert.FromBase64String(RC4TicketClaims));

            return result;
        }

        private static async Task<DecryptedKrbApReq> GeneratePacWithoutClaims()
        {
            var validator = new KerberosValidator(
                new KeyTable(
                    new KerberosKey(
                        "P@ssw0rd!",
                        principalName: new PrincipalName(
                            PrincipalNameType.NT_PRINCIPAL,
                            "CORP.IDENTITYINTERVENTION.com",
                            new[] { "app2@corp.identityintervention.com" }
                        ),
                        saltType: SaltType.ActiveDirectoryUser
                    )
                )
            )
            { ValidateAfterDecrypt = DefaultActions };

            return await validator.Validate(Convert.FromBase64String(S4UProxyTicket));
        }

        private static T TestPacEncoding<T>(T thing)
            where T : PacObject, new()
        {
            var encoded = thing.Marshal();

            var decodedThing = new T();

            decodedThing.Unmarshal(encoded.ToArray());

            return decodedThing;
        }

        [TestMethod]
        public async Task PacDelegationInfo()
        {
            var pac = await GeneratePac(false);

            var deleg = pac.DelegationInformation;

            Assert.AreEqual("host/down2\0", deleg.S4U2ProxyTarget.ToString());
        }

        [TestMethod]
        public async Task PacDelegationInfoRoundtrip()
        {
            var pac = await GeneratePac(false);

            var deleg = pac.DelegationInformation;

            Assert.AreEqual("host/down2\0", deleg.S4U2ProxyTarget.ToString());

            var decoded = TestPacEncoding(deleg);

            Assert.IsNotNull(decoded);

            Assert.AreEqual(deleg.S4U2ProxyTarget, decoded.S4U2ProxyTarget);

            for (var i = 0; i < deleg.S4UTransitedServices.Count(); i++)
            {
                Assert.AreEqual(deleg.S4UTransitedServices.ElementAt(i), decoded.S4UTransitedServices.ElementAt(i));
            }
        }

        [TestMethod]
        public async Task PacClientInfoRoundtrip()
        {
            var pac = await GeneratePac(true);

            var client = pac.ClientInformation;

            var clientDecoded = TestPacEncoding(client);

            Assert.AreEqual("Administrator", clientDecoded.Name);
        }

        [TestMethod]
        public async Task PacServerSignatureRoundtrip()
        {
            var pac = await GeneratePac(true);

            var signature = pac.ServerSignature;

            var signatureDecoded = TestPacEncoding(signature);

            Assert.IsTrue(signature.Signature.Span.SequenceEqual(signatureDecoded.Signature.Span));
        }

        [TestMethod]
        public async Task NdrClaimsRoundtrip()
        {
            var pac = await GeneratePac(true);

            var claims = pac.ClientClaims;

            var claimsDecoded = TestPacEncoding(claims);

            Assert.IsNotNull(claimsDecoded);

            Assert.AreEqual(claims.ClaimsSet.ClaimsArray.Count(), claimsDecoded.ClaimsSet.ClaimsArray.Count());

            for (var i = 0; i < claims.ClaimsSet.ClaimsArray.Count(); i++)
            {
                var left = claims.ClaimsSet.ClaimsArray.ElementAt(i);
                var right = claimsDecoded.ClaimsSet.ClaimsArray.ElementAt(i);

                Assert.AreEqual(left.ClaimSource, right.ClaimSource);

                Assert.AreEqual(left.ClaimEntries.Count(), right.ClaimEntries.Count());

                for (var c = 0; c < left.ClaimEntries.Count(); c++)
                {
                    var claimLeft = left.ClaimEntries.ElementAt(c);
                    var claimRight = right.ClaimEntries.ElementAt(c);

                    Assert.AreEqual(claimLeft.Type, claimRight.Type);
                    Assert.AreEqual(claimLeft.Id, claimRight.Id);
                    Assert.AreEqual(claimLeft.Values.Count(), claimRight.Values.Count());

                    Assert.IsTrue(claimLeft.Values.SequenceEqual(claimRight.Values));
                }
            }
        }

        [TestMethod]
        public async Task NdrLogonInfoRoundtrip()
        {
            var pac = await GeneratePac(true);

            var logonInfo = pac.LogonInfo;

            var logonInfoDecoded = TestPacEncoding(logonInfo);

            Assert.IsNotNull(logonInfoDecoded);

            AssertEqualLogonInfo(logonInfo, logonInfoDecoded);
        }

        [TestMethod]
        public async Task NdrUpnInfoRoundtrip()
        {
            var pac = await GeneratePac(true);

            var upnInfo = pac.UpnDomainInformation;

            var upnInfoDecoded = TestPacEncoding(upnInfo);

            Assert.IsNotNull(upnInfoDecoded);

            Assert.AreEqual("Administrator@identityintervention.com", upnInfoDecoded.Upn);
        }

        private static void AssertEqualLogonInfo(PacLogonInfo left, PacLogonInfo right)
        {
            Assert.AreEqual(left.DomainName, right.DomainName);
            Assert.AreEqual(left.UserName, right.UserName);

            AssertSidsAreEqual(left.DomainSid, right.DomainSid);
            AssertSidsAreEqual(left.UserSid, right.UserSid);

            Assert.AreEqual(left.GroupSids.Count(), right.GroupSids.Count());

            AssertSidsAreEqual(left.GroupSids, right.GroupSids);

            Assert.AreEqual(left.ExtraSids.Count(), right.ExtraSids.Count());

            AssertSidsAreEqual(left.ExtraSids, right.ExtraSids);
        }

        private static void AssertSidsAreEqual(IEnumerable<SecurityIdentifier> leftSids, IEnumerable<SecurityIdentifier> rightSids)
        {
            for (var i = 0; i < leftSids.Count(); i++)
            {
                var leftSid = leftSids.ElementAt(i);
                var rightSid = rightSids.ElementAt(i);

                AssertSidsAreEqual(leftSid, rightSid);
            }
        }

        private static void AssertSidsAreEqual(SecurityIdentifier leftSid, SecurityIdentifier rightSid)
        {
            Assert.AreEqual(leftSid.Value, rightSid.Value);
            Assert.AreEqual(leftSid.Attributes, rightSid.Attributes);
        }
    }
}
