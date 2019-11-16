using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using Tests.Kerberos.NET.Pac.Interop;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class RpcInteropTests
    {
        private const string pac =
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

        private enum PacType
        {
            LOGON_INFO = 1,
            CREDENTIAL_TYPE = 2,
            SERVER_CHECKSUM = 6,
            PRIVILEGE_SERVER_CHECKSUM = 7,
            CLIENT_NAME_TICKET_INFO = 0x0000000A,
            CONSTRAINED_DELEGATION_INFO = 0x0000000B,
            UPN_DOMAIN_INFO = 0x0000000C,
            CLIENT_CLAIMS = 0x0000000D,
            DEVICE_INFO = 0x0000000E,
            DEVICE_CLAIMS = 0x0000000F
        }

        [TestMethod]
        public void MarshalNativeFromNative_Baseline_DoesntExplode()
        {
            var buffers = Setup();

            var kerbInfoBuffer = buffers[PacType.LOGON_INFO];

            var info = UnmarshalValidationInfo(kerbInfoBuffer);

            Assert.IsNotNull(info);
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

            ;
        }

        private const long TicksPerDay = 864000000000L;
        private const long DaysTo1601 = 584388;
        private const long FileTimeOffset = DaysTo1601 * TicksPerDay;

        [TestMethod]
        public void FileTimeConversion()
        {
            //636369481921808216 4049749848 30607508
            var expected = 636369481921808216L;

            uint low = 4049749848;
            uint high = 30607508;

            var fileTime = ((long)high << 32) | low;

            var universalTicks = fileTime + FileTimeOffset;

            Assert.AreEqual(expected, universalTicks);

            var dt = DateTime.FromFileTimeUtc(fileTime);

            Assert.AreEqual(expected, dt.Ticks);

            var offset = dt.Ticks - FileTimeOffset;

            var finalLow = unchecked((uint)offset << 32);
            uint finalHigh = (uint)unchecked(offset >> 32);

            Assert.AreEqual(low, finalLow);
            Assert.AreEqual(high, (uint)finalHigh);
        }

        [TestMethod]
        public void MarshalNativeFromNative_PassThroughManaged()
        {
            var buffers = Setup();

            var kerbInfoBuffer = buffers[PacType.LOGON_INFO];

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(kerbInfoBuffer);

            var kerbInfoBuffer2 = logonInfoDecoded.Encode();

            AssertSequenceEqual(kerbInfoBuffer.Span, kerbInfoBuffer2.Span);

            var final = UnmarshalValidationInfo(kerbInfoBuffer);

            Assert.IsNotNull(final);

            Assert.AreEqual(logonInfoDecoded.DomainName.ToString(), final.LogonDomainName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserName.ToString(), final.EffectiveName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserDisplayName.ToString(), final.FullName.ToString());
            Assert.AreEqual(logonInfoDecoded.ServerName.ToString(), final.LogonServer.ToString());
        }

        private static KERB_VALIDATION_INFO UnmarshalValidationInfo(ReadOnlyMemory<byte> kerbInfoBuffer)
        {
            return Unmarshal<KERB_VALIDATION_INFO>(kerbInfoBuffer, RpcFormatter.Pac, RpcFormatter.KerbValidationInfo);
        }

        [TestMethod]
        public void MarshalNativeFromManaged_Baseline_DoesntExplode()
        {
            var principal = new FakeKerberosPrincipal("user@test.com");

            var pac = principal.GeneratePac().GetAwaiter().GetResult();

            var encodedLogonInfo = pac.LogonInfo.Encode();

            Assert.IsNotNull(encodedLogonInfo);
            Assert.IsTrue(encodedLogonInfo.Length > 0);

            var logonInfoDecoded = new PacLogonInfo();
            logonInfoDecoded.Unmarshal(encodedLogonInfo);

            Assert.AreEqual("user@test.com", logonInfoDecoded.UserName.ToString());

            var nativeDecoded = UnmarshalValidationInfo(encodedLogonInfo);

            Assert.IsNotNull(nativeDecoded);

            Assert.AreEqual(logonInfoDecoded.DomainName.ToString(), nativeDecoded.LogonDomainName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserName.ToString(), nativeDecoded.EffectiveName.ToString());
            Assert.AreEqual(logonInfoDecoded.UserDisplayName.ToString(), nativeDecoded.FullName.ToString());
            Assert.AreEqual(logonInfoDecoded.ServerName.ToString(), nativeDecoded.LogonServer.ToString());
        }

        private static T Unmarshal<T>(ReadOnlyMemory<byte> buffer, ReadOnlyMemory<byte> format, int offset)
        {
            using (var marshaller = new PickleMarshaller(format, offset))
            {
                return marshaller.Decode<T>(buffer.Span);
            }
        }

        private static Dictionary<PacType, ReadOnlyMemory<byte>> Setup()
        {
            var pacBytes = Convert.FromBase64String(pac);

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
    }
}
