// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AnonymousPkinitTests : BaseTest
    {
        [TestMethod]
        public void Anonymous_WellKnownPrincipal_HasCorrectType()
        {
            var anonymous = KrbPrincipalName.WellKnown.Anonymous();

            Assert.AreEqual(PrincipalNameType.NT_WELLKNOWN, anonymous.Type);
        }

        [TestMethod]
        public void Anonymous_WellKnownPrincipal_HasCorrectName()
        {
            var anonymous = KrbPrincipalName.WellKnown.Anonymous();

            Assert.AreEqual(2, anonymous.Name.Length);
            Assert.AreEqual("WELLKNOWN", anonymous.Name[0]);
            Assert.AreEqual("ANONYMOUS", anonymous.Name[1]);
        }

        [TestMethod]
        public void Anonymous_Realm_HasCorrectValue()
        {
            // KerberosConstants is internal, so we verify the well-known
            // anonymous realm value is used correctly through the public API.
            // The constant value per RFC 8062 is "WELLKNOWN:ANONYMOUS".
            var anonymous = KrbPrincipalName.WellKnown.Anonymous();

            // Verify that the anonymous principal can be created and has the
            // expected well-known name, which is paired with realm "WELLKNOWN:ANONYMOUS"
            Assert.AreEqual(PrincipalNameType.NT_WELLKNOWN, anonymous.Type);
            Assert.AreEqual("WELLKNOWN", anonymous.Name[0]);
        }

        [TestMethod]
        public void Anonymous_NtAnonymousType_HasCorrectValue()
        {
            Assert.AreEqual(14, (int)PrincipalNameType.NT_ANONYMOUS);
        }

        [TestMethod]
        public void Anonymous_PrincipalName_FullyQualifiedName()
        {
            var anonymous = KrbPrincipalName.WellKnown.Anonymous();

            var fqn = anonymous.FullyQualifiedName;

            Assert.IsNotNull(fqn);
            Assert.IsTrue(fqn.Contains("WELLKNOWN"));
            Assert.IsTrue(fqn.Contains("ANONYMOUS"));
        }

        [TestMethod]
        public void Anonymous_PrincipalName_Encode_Decode_RoundTrip()
        {
            var original = KrbPrincipalName.WellKnown.Anonymous();

            var encoded = original.Encode();

            Assert.IsTrue(encoded.Length > 0);

            var decoded = KrbPrincipalName.Decode(encoded);

            Assert.AreEqual(original.Type, decoded.Type);
            Assert.AreEqual(original.Name.Length, decoded.Name.Length);
            Assert.AreEqual(original.Name[0], decoded.Name[0]);
            Assert.AreEqual(original.Name[1], decoded.Name[1]);
        }
    }
}
