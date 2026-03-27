// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class PacExtensionTests : BaseTest
    {
        [TestMethod]
        public void PacAttributesInfo_RoundTrip_PacWasRequested()
        {
            var original = new PacAttributesInfo
            {
                FlagsLength = 32,
                Flags = PacAttributeFlags.PacWasRequested
            };

            var marshalled = original.Marshal();

            var restored = new PacAttributesInfo();
            restored.Unmarshal(marshalled);

            Assert.AreEqual(original.FlagsLength, restored.FlagsLength);
            Assert.AreEqual(original.Flags, restored.Flags);
        }

        [TestMethod]
        public void PacAttributesInfo_PacType_IsAttributesInfo()
        {
            var info = new PacAttributesInfo();

            Assert.AreEqual(PacType.ATTRIBUTES_INFO, info.PacType);
        }

        [TestMethod]
        public void PacAttributesInfo_PacWasGivenImplicitly_RoundTrips()
        {
            var original = new PacAttributesInfo
            {
                FlagsLength = 32,
                Flags = PacAttributeFlags.PacWasGivenImplicitly
            };

            var marshalled = original.Marshal();

            var restored = new PacAttributesInfo();
            restored.Unmarshal(marshalled);

            Assert.AreEqual(PacAttributeFlags.PacWasGivenImplicitly, restored.Flags);
        }

        [TestMethod]
        public void PacAttributesInfo_DefaultFlagsLength_Is32()
        {
            var info = new PacAttributesInfo();

            Assert.AreEqual(32, info.FlagsLength);
        }

        [TestMethod]
        public void PacRequestor_RoundTrip_Sid()
        {
            var sid = new SecurityIdentifier(
                IdentifierAuthority.NTAuthority,
                new uint[] { 123, 456, 789 },
                SidAttributes.SE_GROUP_ENABLED
            );

            var original = new PacRequestor
            {
                RequestorSid = sid
            };

            var marshalled = original.Marshal();

            var restored = new PacRequestor();
            restored.Unmarshal(marshalled);

            Assert.AreEqual(sid.Value, restored.RequestorSid.Value);
        }

        [TestMethod]
        public void PacRequestor_PacType_IsRequestor()
        {
            var requestor = new PacRequestor();

            Assert.AreEqual(PacType.REQUESTOR, requestor.PacType);
        }

        [TestMethod]
        public void PacType_TicketChecksum_Is0x10()
        {
            Assert.AreEqual(0x10, (int)PacType.TICKET_CHECKSUM);
        }

        [TestMethod]
        public void PacType_AttributesInfo_Is0x11()
        {
            Assert.AreEqual(0x11, (int)PacType.ATTRIBUTES_INFO);
        }

        [TestMethod]
        public void PacType_Requestor_Is0x12()
        {
            Assert.AreEqual(0x12, (int)PacType.REQUESTOR);
        }

        [TestMethod]
        public void PacType_FullChecksum_Is0x13()
        {
            Assert.AreEqual(0x13, (int)PacType.FULL_CHECKSUM);
        }

        [TestMethod]
        public void KnownTypes_ContainsAllNewPacTypes()
        {
            var knownTypesField = typeof(PrivilegedAttributeCertificate)
                .GetField("KnownTypes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            Assert.IsNotNull(knownTypesField, "KnownTypes field not found");

            var knownTypes = (System.Collections.Generic.Dictionary<PacType, System.Type>)knownTypesField.GetValue(null);

            Assert.IsTrue(knownTypes.ContainsKey(PacType.TICKET_CHECKSUM), "KnownTypes missing TICKET_CHECKSUM");
            Assert.IsTrue(knownTypes.ContainsKey(PacType.ATTRIBUTES_INFO), "KnownTypes missing ATTRIBUTES_INFO");
            Assert.IsTrue(knownTypes.ContainsKey(PacType.REQUESTOR), "KnownTypes missing REQUESTOR");
            Assert.IsTrue(knownTypes.ContainsKey(PacType.FULL_CHECKSUM), "KnownTypes missing FULL_CHECKSUM");
        }
    }
}
