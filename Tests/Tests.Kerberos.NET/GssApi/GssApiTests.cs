// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities.GssApi;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET.GssApi
{
    [TestClass]
    public class GssApiTests : BaseTest
    {
        [TestMethod]
        public void GssContext_CreateInstance()
        {
            using (var context = new GssContext())
            {
                Assert.IsNotNull(context);
            }
        }

        [TestMethod]
        public void GssStatus_Complete()
        {
            var status = GssStatus.Complete;
            Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status.MajorStatus);
            Assert.IsTrue(status.IsSuccess);
            Assert.IsFalse(status.IsContinueNeeded);
        }

        [TestMethod]
        public void GssStatus_ContinueNeeded()
        {
            var status = GssStatus.ContinueNeeded;
            Assert.AreEqual(GssMajorStatus.GSS_S_CONTINUE_NEEDED, status.MajorStatus);
            Assert.IsFalse(status.IsSuccess);
            Assert.IsTrue(status.IsContinueNeeded);
        }

        [TestMethod]
        public void GssBuffer_CreateEmpty()
        {
            using (var buffer = new GssBuffer())
            {
                Assert.IsNotNull(buffer);
                Assert.IsTrue(buffer.IsEmpty);
                Assert.AreEqual(0, buffer.Length);
            }
        }

        [TestMethod]
        public void GssBuffer_CreateWithData()
        {
            var data = new byte[] { 1, 2, 3, 4, 5 };
            using (var buffer = new GssBuffer(data))
            {
                Assert.IsNotNull(buffer);
                Assert.IsFalse(buffer.IsEmpty);
                Assert.AreEqual(5, buffer.Length);
                CollectionAssert.AreEqual(data, buffer.ToArray());
            }
        }

        [TestMethod]
        public void GssName_CreateAndDisplay()
        {
            var name = new GssName("user@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);
            Assert.IsNotNull(name);
            Assert.AreEqual("user@REALM.COM", name.Name);
            Assert.AreEqual(GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME, name.NameType);
            Assert.IsFalse(name.IsMechanismName);
        }

        [TestMethod]
        public void GssOid_Equality()
        {
            var oid1 = new GssOid("1.2.840.113554.1.2.2");
            var oid2 = new GssOid("1.2.840.113554.1.2.2");
            var oid3 = new GssOid("1.2.840.113554.1.2.1");

            Assert.AreEqual(oid1, oid2);
            Assert.AreNotEqual(oid1, oid3);
            Assert.IsTrue(oid1 == oid2);
            Assert.IsTrue(oid1 != oid3);
        }

        [TestMethod]
        public void GssOidSet_AddAndContains()
        {
            using (var oidSet = new GssOidSet())
            {
                Assert.AreEqual(0, oidSet.Count);

                oidSet.Add(GssOid.GSS_MECH_KRB5);
                Assert.AreEqual(1, oidSet.Count);
                Assert.IsTrue(oidSet.Contains(GssOid.GSS_MECH_KRB5));

                // Adding duplicate should not increase count
                oidSet.Add(GssOid.GSS_MECH_KRB5);
                Assert.AreEqual(1, oidSet.Count);

                oidSet.Add(GssOid.GSS_MECH_SPNEGO);
                Assert.AreEqual(2, oidSet.Count);
                Assert.IsTrue(oidSet.Contains(GssOid.GSS_MECH_SPNEGO));
            }
        }

        [TestMethod]
        public void GssContext_IndicateMechs()
        {
            using (var context = new GssContext())
            {
                var status = context.GSS_Indicate_mechs(out GssOidSet mechSet, out uint minorStatus);

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(mechSet);
                Assert.IsTrue(mechSet.Count > 0);
                Assert.IsTrue(mechSet.Contains(GssOid.GSS_MECH_KRB5));
            }
        }

        [TestMethod]
        public void GssContext_CreateEmptyOidSet()
        {
            using (var context = new GssContext())
            {
                var status = context.GSS_Create_empty_OID_set(out GssOidSet oidSet, out uint minorStatus);

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(oidSet);
                Assert.AreEqual(0, oidSet.Count);
            }
        }

        [TestMethod]
        public void GssContext_AddOidSetMember()
        {
            using (var context = new GssContext())
            {
                GssOidSet oidSet = new GssOidSet();
                var status = context.GSS_Add_OID_set_member(
                    GssOid.GSS_MECH_KRB5,
                    ref oidSet,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.AreEqual(1, oidSet.Count);
                Assert.IsTrue(oidSet.Contains(GssOid.GSS_MECH_KRB5));
            }
        }

        [TestMethod]
        public void GssContext_TestOidSetMember()
        {
            using (var context = new GssContext())
            {
                var oidSet = new GssOidSet();
                oidSet.Add(GssOid.GSS_MECH_KRB5);

                var status = context.GSS_Test_OID_set_member(
                    GssOid.GSS_MECH_KRB5,
                    oidSet,
                    out bool present,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsTrue(present);

                status = context.GSS_Test_OID_set_member(
                    GssOid.GSS_MECH_NTLM,
                    oidSet,
                    out present,
                    out minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsFalse(present);
            }
        }

        [TestMethod]
        public void GssContext_CompareName()
        {
            using (var context = new GssContext())
            {
                var name1 = new GssName("user@REALM.COM");
                var name2 = new GssName("user@realm.com");
                var name3 = new GssName("different@REALM.COM");

                var status = context.GSS_Compare_name(
                    name1,
                    name2,
                    out bool nameEqual,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsTrue(nameEqual);

                status = context.GSS_Compare_name(
                    name1,
                    name3,
                    out nameEqual,
                    out minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsFalse(nameEqual);
            }
        }

        [TestMethod]
        public void GssContext_DisplayName()
        {
            using (var context = new GssContext())
            {
                var name = new GssName("user@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);

                var status = context.GSS_Display_name(
                    name,
                    out GssBuffer outputNameBuffer,
                    out GssOid outputNameType,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(outputNameBuffer);
                Assert.AreEqual("user@REALM.COM", Encoding.UTF8.GetString(outputNameBuffer.ToArray()));
                Assert.AreEqual(GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME, outputNameType);
            }
        }

        [TestMethod]
        public void GssContext_ImportName()
        {
            using (var context = new GssContext())
            {
                var nameBytes = Encoding.UTF8.GetBytes("user@REALM.COM");
                var nameBuffer = new GssBuffer(nameBytes);

                var status = context.GSS_Import_name(
                    nameBuffer,
                    GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME,
                    out GssName outputName,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(outputName);
                Assert.AreEqual("user@REALM.COM", outputName.Name);
                Assert.AreEqual(GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME, outputName.NameType);
            }
        }

        [TestMethod]
        public void GssContext_DuplicateName()
        {
            using (var context = new GssContext())
            {
                var srcName = new GssName("user@REALM.COM", GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME);

                var status = context.GSS_Duplicate_name(
                    srcName,
                    out GssName destName,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(destName);
                Assert.AreEqual(srcName.Name, destName.Name);
                Assert.AreEqual(srcName.NameType, destName.NameType);
                Assert.AreNotSame(srcName, destName);
            }
        }

        [TestMethod]
        public void GssContext_CanonicalizeName()
        {
            using (var context = new GssContext())
            {
                var inputName = new GssName("user@REALM.COM");

                var status = context.GSS_Canonicalize_name(
                    inputName,
                    GssOid.GSS_MECH_KRB5,
                    out GssName outputName,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(outputName);
                Assert.IsTrue(outputName.IsMechanismName);
                Assert.AreEqual(GssOid.GSS_MECH_KRB5, outputName.MechanismType);
            }
        }

        [TestMethod]
        public void GssContext_InquireNamesForMech()
        {
            using (var context = new GssContext())
            {
                var status = context.GSS_Inquire_names_for_mech(
                    GssOid.GSS_MECH_KRB5,
                    out GssOidSet nameTypes,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(nameTypes);
                Assert.IsTrue(nameTypes.Count > 0);
                Assert.IsTrue(nameTypes.Contains(GssNameType.GSS_KRB5_NT_PRINCIPAL_NAME));
            }
        }

        [TestMethod]
        public void GssContext_InquireMechsForName()
        {
            using (var context = new GssContext())
            {
                var name = new GssName("user@REALM.COM");

                var status = context.GSS_Inquire_mechs_for_name(
                    name,
                    out GssOidSet mechTypes,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(mechTypes);
                Assert.IsTrue(mechTypes.Count > 0);
            }
        }

        [TestMethod]
        public void GssContext_DisplayStatus()
        {
            using (var context = new GssContext())
            {
                uint messageContext = 0;
                var status = context.GSS_Display_status(
                    (uint)GssMajorStatus.GSS_S_BAD_MECH,
                    1, // GSS_C_GSS_CODE
                    null,
                    ref messageContext,
                    out GssBuffer statusString,
                    out uint minorStatus
                );

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNotNull(statusString);
                Assert.IsFalse(statusString.IsEmpty);
            }
        }

        [TestMethod]
        public void GssContext_ReleaseBuffer()
        {
            using (var context = new GssContext())
            {
                GssBuffer buffer = new GssBuffer(new byte[] { 1, 2, 3 });

                var status = context.GSS_Release_buffer(ref buffer, out uint minorStatus);

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNull(buffer);
            }
        }

        [TestMethod]
        public void GssContext_ReleaseName()
        {
            using (var context = new GssContext())
            {
                GssName name = new GssName("user@REALM.COM");

                var status = context.GSS_Release_name(ref name, out uint minorStatus);

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNull(name);
            }
        }

        [TestMethod]
        public void GssContext_ReleaseOidSet()
        {
            using (var context = new GssContext())
            {
                GssOidSet oidSet = new GssOidSet();
                oidSet.Add(GssOid.GSS_MECH_KRB5);

                var status = context.GSS_Release_OID_set(ref oidSet, out uint minorStatus);

                Assert.AreEqual(GssMajorStatus.GSS_S_COMPLETE, status);
                Assert.IsNull(oidSet);
            }
        }

        [TestMethod]
        public void GssChannelBindings_Create()
        {
            var channelBindings = new GssChannelBindings
            {
                InitiatorAddrType = 0,
                InitiatorAddress = new byte[] { 192, 168, 1, 1 },
                AcceptorAddrType = 0,
                AcceptorAddress = new byte[] { 192, 168, 1, 2 },
                ApplicationData = new byte[] { 1, 2, 3, 4 }
            };

            Assert.IsNotNull(channelBindings);
            Assert.AreEqual(0u, channelBindings.InitiatorAddrType);
            Assert.AreEqual(4, channelBindings.InitiatorAddress.Length);
        }

        [TestMethod]
        public void GssSecurityContext_Create()
        {
            using (var secContext = new GssSecurityContext())
            {
                Assert.IsNotNull(secContext);
                Assert.IsFalse(secContext.IsEstablished);
                Assert.IsFalse(secContext.LocallyInitiated);
            }
        }
    }
}
