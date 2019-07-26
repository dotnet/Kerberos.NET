using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET.Pac
{
    [TestClass]
    public class NdrTests : BaseTest
    {
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

            var pac = result.Ticket.AuthorizationData
                .Where(d => d.Type == AuthorizationDataType.AdIfRelevant)
                .Select(d => d.DecodeAdIfRelevant()
                    .Where(a => a.Type == AuthorizationDataType.AdWin2kPac)
                ).First();

            return new PrivilegedAttributeCertificate(pac.First().Data.ToArray());
        }

        private static async Task<DecryptedKrbApReq> GeneratePacContainingClaims()
        {
            var validator = new KerberosValidator(new KerberosKey("P@ssw0rd!")) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(Convert.FromBase64String(RC4Ticket_Claims));
            return result;
        }

        private static async Task<DecryptedKrbApReq> GeneratePacWithoutClaims()
        {
            var validator = new KerberosValidator(ReadDataFile("rc4-key-data")) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(ReadDataFile("rc4-kerberos-data"));
            return result;
        }

        [TestMethod]
        public async Task TestNdrClaimsRoundtrip()
        {
            var pac = await GeneratePac(true);

            var claims = pac.ClientClaims;

            var stream = new NdrBinaryStream();

            claims.Encode(stream);

            var claimsEncoded = stream.ToMemory();

            var claimsDecoded = new ClaimsSetMetadata(claimsEncoded.ToArray());

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
                    Assert.AreEqual(claimLeft.RawValues.Count(), claimRight.RawValues.Count());

                    Assert.IsTrue(claimLeft.RawValues.SequenceEqual(claimRight.RawValues));
                }
            }
        }

        [TestMethod]
        public async Task TestNdrLogonInfoRoundtrip()
        {
            var pac = await GeneratePac(true);

            var logonInfo = pac.LogonInfo;

            var stream = new NdrBinaryStream();

            logonInfo.Encode(stream);

            Assert.IsNotNull(stream);

            var logonInfoEncoded = stream.ToMemory();

            var logonInfoDecoded = new PacLogonInfo(logonInfoEncoded.ToArray());

            Assert.IsNotNull(logonInfoDecoded);

            AssertEqualPacs(logonInfo, logonInfoDecoded);
        }

        private void AssertEqualPacs(PacLogonInfo left, PacLogonInfo right)
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

            Assert.IsTrue(leftSid.BinaryForm.SequenceEqual(rightSid.BinaryForm));
        }
    }
}
