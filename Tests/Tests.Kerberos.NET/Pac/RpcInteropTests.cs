// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tests.Kerberos.NET.Pac.Interop;

namespace Tests.Kerberos.NET
{
#if X64
    [TestClass]
#endif
    public class RpcInteropTests
    {
        private const string Pac =
            "BgAAAAAAAAABAAAAQAIAAGgAAAAAAAAADQAAABADAACoAgAAAAAAAAoAAAAkAAAAuAUAAAAAAAAMAAAAkAAAAOAFAAA" +
            "AAAAABgAAABQAAABwBgAAAAAAAAcAAAAUAAAAiAYAAAAAAAABEAgAzMzMzDACAAAAAAAAAAACAFhHYvGUCNMB//////" +
            "///3//////////f41sNc1m99IBjSyf9y/40gGN7I7CZxjTARoAGgAEAAIAAAAAAAgAAgAAAAAADAACAAAAAAAQAAIAAAA" +
            "AABQAAgAAAAAAGAACAA4AAAD0AQAAAQIAAAUAAAAcAAIAIAIAAAAAAAAAAAAAAAAAAAAAAAAIAAoAIAACABoAHAAkAAIAKAACAA" +
            "AAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAALAACADgAAgABAAAAPAACAA0AAAAAAAAADQAAAEEAZ" +
            "ABtAGkAbgBpAHMAdAByAGEAdABvAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAAAAAAAFAAAAAAIAAAcAAAABAgAABwAAAAgCAAAHAAAABwIAAAcAAAAGAgAABwAAAAUAAAAAAAAABAAAAEQAQwAwAD" +
            "EADgAAAAAAAAANAAAASQBEAEUATgBUAEkAVABZAEkATgBUAEUAUgAAAAQAAAABBAAAAAAABRUAAADxtzQy8G5m31knUcgCAAAA" +
            "MAACAAcAAAA0AAIABwAAAAUAAAABBQAAAAAABRUAAAAAAAAAAAAAAAAAAADxAQAAAQAAAAEBAAAAAAASAQAAAAQAAAABBAAAAA" +
            "AABRUAAADxtzQy8G5m31knUcgBAAAAPAIAAAcAACABEAgAzMzMzAADAAAAAAAAAAACANsCAAAEAAIABAAAAJAFAAAAAAAAAAAA" +
            "AAAAAADbAgAAdImYmXgACQAHAAgACQAJAAaQmZmZCZmQiXl3hmcICQCZiQkAmQAJAAmQCQAJAAkAaWhmeXcAmGcIh3cAiQkAAA" +
            "kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAAkAkAAAAJYJ" +
            "CQAAAAAAlZcAAAAAAABkdpgAAAAACGUIBwCIAAAAdwgIAAgAAAB1BogACICAYGWIcAAACABgZYeIAAAACIBngAgAAAAAgAAAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADOVPhD/+YhuOn4oARiWy4/9yZAlLsQ6ODCCPZsG" +
            "E3R1rMOxMx2mnsFBK1CEM5z90J+S0qvXSy5o2EPdMwe0Z7xcx4wLQ6TZpMvg2RnTEFuByGILDwNmFeguhDArVLHMd0FlARmyQR" +
            "znJrhgKQqaQh0+ZGVFQh8Y7IOm3BUA5DbKnEpaEqgK0VGt1LejR61FBDgYAMusZHKGM34wxVkiBj8xAaV08QCckqhJJEwcc25X" +
            "vwtMfVwzG4J6ngwhkQ4HpSkAz+T0a+9q8x3TcQN3UqHB4nOMdFO7k7Ji8iAIigAKmQHnfpqbjCjKZJAXrRTHBLE+Mo2xrxIhwo" +
            "EIeXh5FcEa/rHDF1lqod8iB7DSXiI4GWEAxTK+jIRCyt8H0XkYPJnvYiPFXuayHVn2r4Lor4UASIuqmmyJ0pGgLXO6ACxm80mj" +
            "A2qUgH6LgmarDIqYTaGVEDKJtm1T6AsE+x6m8kSJbB3w0a09QOzz6KWdDjQPVooAEpjfir1WIzEeFdDjA77CtThTxwoIDYgqSP" +
            "4idVqCkbhfNRBYeK7VlV1TFesVkebKAOZq2zwj4edMSfkEUlTk/Vd4cLLB1zFkDXeyRmLKifYi66LkenAWTlcAJMFByg3VGouM" +
            "/wDwAAAAACFeIJcI0wEaAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAAAAAAEwAEAAwAGAAAQAAAAAAAABBAGQAbQBpAG4AaQ" +
            "BzAHQAcgBhAHQAbwByAEAAaQBkAGUAbgB0AGkAdAB5AGkAbgB0AGUAcgB2AGUAbgB0AGkAbwBuAC4AYwBvAG0AAAAAAEkARABF" +
            "AE4AVABJAFQAWQBJAE4AVABFAFIAVgBFAE4AVABJAE8ATgAuAEMATwBNAHb///9hy/kO3YA+1cGWwI/WU46AAAAAAHb///+ITA" +
            "Pw8wujGdvZ025F8b7zAAAAAA==";

        [TestMethod]
        public void MarshalNativeFromNative_Baseline_DoesntExplode()
        {
            var buffers = Setup();

            var kerbInfoBuffer = buffers[PacType.LOGON_INFO];

            var handle = UnmarshalValidationInfo(kerbInfoBuffer);

            var info = handle.Value;

            Assert.IsNotNull(info);

            Assert.AreEqual("IDENTITYINTER\0", info.LogonDomainName.ToString());
            Assert.AreEqual("Administrator", info.EffectiveName.ToString());
            Assert.AreEqual(string.Empty, info.FullName.ToString());
            Assert.AreEqual("DC01\0", info.LogonServer.ToString());

            handle.Close();
        }

        [TestMethod]
        public void FileTimeConversion()
        {
            var expected = 636369481921808216L;

            var ft = new RpcFileTime { LowDateTime = 4049749848, HighDateTime = 30607508 };

            var dt = (DateTimeOffset)ft;

            Assert.AreEqual(expected, dt.Ticks);

            uint low = ft.LowDateTime;
            uint high = ft.HighDateTime;

            ft = dt;

            Assert.AreEqual(low, ft.LowDateTime);
            Assert.AreEqual(high, ft.HighDateTime);
        }

        [TestMethod]
        public unsafe void MarshalNativeFromNative_PassThroughManaged()
        {
            var buffers = Setup();

            var kerbInfoBuffer = buffers[PacType.LOGON_INFO];

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(kerbInfoBuffer);

            var kerbInfoBuffer2 = logonInfoDecoded.Encode();

            AssertSequenceEqual(kerbInfoBuffer.Span, kerbInfoBuffer2.Span);

            AssertManagedMatchesNative(logonInfoDecoded, kerbInfoBuffer2);
        }

        [TestMethod]
        public void MarshalNativeFromNative_PassThroughManagedRoundtripped()
        {
            var buffers = Setup();

            var kerbInfoBuffer = buffers[PacType.LOGON_INFO];

            ReadOnlyMemory<byte> encoded;

            for (var i = 0; i < 100; i++)
            {
                var logonInfoDecoded = new PacLogonInfo();
                logonInfoDecoded.Unmarshal(kerbInfoBuffer);

                encoded = logonInfoDecoded.Encode();

                var kerbInfoBuffer2 = new ReadOnlyMemory<byte>(encoded.ToArray());

                AssertSequenceEqual(kerbInfoBuffer.Span, kerbInfoBuffer2.Span);

                // for unknown reasons NdrMesTypeDecode2 will modify kerbInfoBuffer2[16]
                // which is the private structure referral pointer
                // this limits the validity of this test, but it is interesting nonetheless

                AssertManagedMatchesNative(logonInfoDecoded, kerbInfoBuffer2);

                kerbInfoBuffer = encoded;
            }
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Baseline_DoesntExplode()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac();

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            AssertManagedMatchesNative(logonInfoDecoded, encodedLogonInfo);
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Groups()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac();

            GeneratePacExtensions(pac, includeGroups: true, includeExtraIds: false, includeResourceDomain: false, includeResourceGroups: false);

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            AssertManagedMatchesNative(logonInfoDecoded, encodedLogonInfo);
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Groups_ExtraSids()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac();

            GeneratePacExtensions(pac, includeGroups: true, includeExtraIds: true, includeResourceDomain: false, includeResourceGroups: false);

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            AssertManagedMatchesNative(logonInfoDecoded, encodedLogonInfo);
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Groups_ExtraSids_ResourceDomain()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac();

            GeneratePacExtensions(pac, includeGroups: true, includeExtraIds: true, includeResourceDomain: true, includeResourceGroups: false);

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            AssertManagedMatchesNative(logonInfoDecoded, encodedLogonInfo);
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Groups_ExtraSids_ResourceDomain_ResourceDomainGroups()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac();

            GeneratePacExtensions(pac, includeGroups: true, includeExtraIds: true, includeResourceDomain: true, includeResourceGroups: true);

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            AssertManagedMatchesNative(logonInfoDecoded, encodedLogonInfo);
        }

        private static void GeneratePacExtensions(
            PrivilegedAttributeCertificate pac,
            bool includeGroups,
            bool includeExtraIds,
            bool includeResourceDomain,
            bool includeResourceGroups
        )
        {
            if (includeGroups)
            {
                pac.LogonInfo.GroupIds = Enumerable.Range(23, 100).Select(g => new GroupMembership()
                {
                    Attributes = SidAttributes.SE_GROUP_ENABLED,
                    RelativeId = (uint)g
                });

                Assert.AreEqual(100, pac.LogonInfo.GroupCount);
            }

            if (includeExtraIds)
            {
                pac.LogonInfo.ExtraIds = Enumerable.Range(45, 100).Select(e => new RpcSidAttributes
                {
                    Attributes = SidAttributes.SE_GROUP_INTEGRITY,
                    Sid = new SecurityIdentifier(
                        IdentifierAuthority.CreatorAuthority,
                        new uint[] { 123, 321, 456, 432, (uint)e },
                        SidAttributes.SE_GROUP_USE_FOR_DENY_ONLY
                    ).ToRpcSid()
                });

                Assert.AreEqual(100, pac.LogonInfo.ExtraSidCount);
            }

            if (includeResourceDomain)
            {
                pac.LogonInfo.ResourceDomainId = new SecurityIdentifier(
                    IdentifierAuthority.AppPackageAuthority,
                    new uint[] { 111, 222, 333, 444 },
                    SidAttributes.SE_GROUP_RESOURCE
                ).ToRpcSid();
            }

            if (includeResourceGroups)
            {
                pac.LogonInfo.ResourceGroupIds = Enumerable.Range(88, 100).Select(g => new GroupMembership()
                {
                    Attributes = SidAttributes.SE_GROUP_USE_FOR_DENY_ONLY,
                    RelativeId = (uint)g
                });

                Assert.AreEqual(100, pac.LogonInfo.ResourceGroupCount);
            }
        }

        private static SafeMarshalledHandle<T> Unmarshal<T>(ReadOnlyMemory<byte> buffer, ReadOnlyMemory<byte> format, int offset)
            where T : unmanaged
        {
            using (var marshaller = new PickleMarshaller(format, offset))
            {
                return marshaller.Decode(buffer.Span, p => ConvertThing<T>(p));
            }
        }

        private static unsafe T ConvertThing<T>(IntPtr p)
            where T : unmanaged
        {
            T* pThing = (T*)p;

            return *pThing;
        }

        private static Dictionary<PacType, ReadOnlyMemory<byte>> Setup()
        {
            var pacBytes = Convert.FromBase64String(Pac);

            using (var reader = new BinaryReader(new MemoryStream(pacBytes)))
            {
                var buffers = new Dictionary<PacType, ReadOnlyMemory<byte>>();

                var count = reader.ReadInt32();
                var ver = reader.ReadInt32();

                for (var i = 0; i < count; i++)
                {
                    var type = (PacType)reader.ReadInt32();
                    var size = reader.ReadInt32();
                    var offset = reader.ReadInt64();

                    buffers[type] = new ReadOnlyMemory<byte>(pacBytes).Slice((int)offset, size);
                }

                return buffers;
            }
        }

        private static unsafe void AssertManagedMatchesNative(PacLogonInfo logonInfoDecoded, ReadOnlyMemory<byte> kerbInfoBuffer2)
        {
            var handle = UnmarshalValidationInfo(kerbInfoBuffer2);

            var final = handle.Value;

            Assert.IsNotNull(final);

            Assert.AreEqual(logonInfoDecoded.DomainName.ToString(), final.LogonDomainName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserName.ToString(), final.EffectiveName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserDisplayName.ToString(), final.FullName.ToString());
            Assert.AreEqual(logonInfoDecoded.ServerName.ToString(), final.LogonServer.ToString());

            Assert.AreEqual(logonInfoDecoded.DomainSid, final.LogonDomainId->ToSecurityIdentifier());

            Assert.AreEqual(logonInfoDecoded.UserId, final.UserId);

            Assert.AreEqual(logonInfoDecoded.GroupCount, (int)final.GroupCount);

            if (logonInfoDecoded.GroupCount > 0)
            {
                AssertGroupMembershipsMatch(logonInfoDecoded.GroupIds, final.GroupIds);
            }

            Assert.AreEqual(logonInfoDecoded.ExtraSidCount, (int)final.SidCount);

            for (var i = 0; i < logonInfoDecoded.ExtraSidCount; i++)
            {
                var expected = logonInfoDecoded.ExtraIds.ElementAt(i);
                var actual = final.ExtraSids[i];

                Assert.AreEqual(expected.Attributes, actual.Attributes);
                Assert.AreEqual(expected.Sid.ToSecurityIdentifier(), actual.Sid->ToSecurityIdentifier());
            }

            Assert.AreEqual(logonInfoDecoded.ResourceDomainId == null, final.ResourceGroupDomainSid == null);

            if (logonInfoDecoded.ResourceDomainId != null)
            {
                Assert.AreEqual(logonInfoDecoded.ResourceDomainSid, final.ResourceGroupDomainSid->ToSecurityIdentifier());
            }

            Assert.AreEqual(logonInfoDecoded.ResourceGroupCount, (int)final.ResourceGroupCount);

            if (logonInfoDecoded.ResourceGroupCount > 0)
            {
                AssertGroupMembershipsMatch(logonInfoDecoded.ResourceGroupIds, final.ResourceGroupIds);
            }

            handle.Close();
        }

        private static unsafe void AssertGroupMembershipsMatch(IEnumerable<GroupMembership> expectedGroups, GROUP_MEMBERSHIP* actualGroups)
        {
            for (var i = 0; i < expectedGroups.Count(); i++)
            {
                var expected = expectedGroups.ElementAt(i);
                var actual = actualGroups[i];

                Assert.AreEqual(expected.Attributes, actual.Attributes);
                Assert.AreEqual(expected.RelativeId, actual.RelativeId);
            }
        }

        private static SafeMarshalledHandle<KERB_VALIDATION_INFO> UnmarshalValidationInfo(ReadOnlyMemory<byte> kerbInfoBuffer)
        {
            return Unmarshal<KERB_VALIDATION_INFO>(kerbInfoBuffer, RpcFormatter.Pac, RpcFormatter.KerbValidationInfo);
        }

        private static void AssertSequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
        {
            var diff = expected.Length - actual.Length;

            if (diff != 0)
            {
                Assert.Fail($"Lengths don't match. Expected: {expected.Length}; Actual: {actual.Length}");
            }

            Hex.Debug(expected.Slice(0).ToArray());
            Hex.Debug(actual.Slice(0).ToArray());

            for (var i = 0; i < expected.Length; i++)
            {
                var expectedAt = expected[i];
                var actualAt = actual[i];

                try
                {
                    Assert.AreEqual(expectedAt, actualAt, $"Equality failed at index {i} with expected {expectedAt} != {actualAt} actual");
                }
                catch (AssertFailedException)
                {
                    Hex.Debug(expected.Slice(i).ToArray());
                    Hex.Debug(actual.Slice(i).ToArray());
                    throw;
                }
            }
        }
    }
}