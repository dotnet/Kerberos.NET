using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET.SourceGenerator
{
    /// <summary>
    /// Verifies the public API surface of source-generated ASN.1 types.
    /// These tests catch regressions from the XML/XSLT → source generator migration
    /// by asserting that all expected types, properties, and methods still exist with
    /// the correct signatures.
    /// </summary>
    [TestClass]
    public class GeneratedApiSurfaceTests
    {
        private static readonly Assembly EntitiesAssembly = typeof(KrbAsReq).Assembly;

        // ────────────────────────────────────────────────────────
        // Expected types (all must exist in Kerberos.NET.Entities)
        // ────────────────────────────────────────────────────────

        private static readonly string[] ExpectedTypes = new[]
        {
            // Core Kerberos types (RFC 4120)
            "KrbTicket", "KrbEncTicketPart", "KrbAuthenticator",
            "KrbAsReq", "KrbAsRep", "KrbTgsReq", "KrbTgsRep",
            "KrbKdcReq", "KrbKdcReqBody", "KrbKdcRep", "KrbEncKdcRepPart",
            "KrbEncAsRepPart", "KrbEncTgsRepPart",
            "KrbApReq", "KrbApRep", "KrbEncApRepPart",
            "KrbError", "KrbPaData", "KrbPrincipalName",
            "KrbEncryptedData", "KrbEncryptionKey", "KrbChecksum",
            "KrbHostAddress", "KrbTransitedEncoding",
            "KrbAuthorizationData", "KrbAuthorizationDataSequence",
            "KrbLastReq", "KrbPaEncTsEnc", "KrbMethodData",
            "KrbCred", "KrbEncKrbCredPart", "KrbCredInfo",
            "KrbPriv", "KrbEncKrbPrivPart",
            "KrbETypeInfo2", "KrbETypeInfo2Entry",
            "KrbETypeList", "KrbErrorData",

            // SPNEGO (RFC 4178)
            "NegotiationToken", "NegTokenInit", "NegTokenResp",

            // PKINIT (RFC 4556)
            "KrbPaPkAsReq", "KrbPaPkAsRep",
            "KrbAuthPack", "KrbPKAuthenticator",
            "KrbDHReplyInfo", "KrbKdcDHKeyInfo",
            "KrbAlgorithmIdentifier", "KrbSubjectPublicKeyInfo",
            "KrbExternalPrincipalIdentifier",
            "KrbDiffieHellmanDomainParameters",
            "KrbDiffieHellmanValidationParameters",

            // FAST (RFC 6113)
            "KrbFastReq", "KrbFastResponse",
            "KrbFastArmor", "KrbFastArmoredReq", "KrbFastArmoredRep",
            "KrbFastFinished",
            "KrbPaFxFastRequest", "KrbPaFxFastReply",
            "KrbPaAuthenticationSet", "KrbPaAuthenticationSetElement",

            // Extensions
            "KrbPaForUser", "KrbPaPacRequest", "KrbPaPacOptions",
            "KrbPaS4uX509User", "KrbS4uUserId", "KrbPaSvrReferralData",
            "KrbChangePasswdData", "KdcProxyMessage",
            "IAKerbHeader",
        };

        [TestMethod]
        public void AllExpectedTypesExist()
        {
            var missing = new List<string>();

            foreach (var typeName in ExpectedTypes)
            {
                var type = EntitiesAssembly.GetType($"Kerberos.NET.Entities.{typeName}");

                if (type == null)
                {
                    missing.Add(typeName);
                }
            }

            Assert.AreEqual(0, missing.Count,
                $"Missing types: {string.Join(", ", missing)}");
        }

        [TestMethod]
        public void AllGeneratedTypesArePartialClasses()
        {
            foreach (var typeName in ExpectedTypes)
            {
                var type = EntitiesAssembly.GetType($"Kerberos.NET.Entities.{typeName}");
                Assert.IsNotNull(type, $"Type {typeName} not found");
                Assert.IsTrue(type.IsClass, $"{typeName} should be a class");
                Assert.IsTrue(type.IsPublic, $"{typeName} should be public");
            }
        }

        // ────────────────────────────────────────────────────────
        // Property signatures for key types
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbTicket), "TicketNumber", typeof(int))]
        [DataRow(typeof(KrbTicket), "Realm", typeof(string))]
        [DataRow(typeof(KrbTicket), "SName", typeof(KrbPrincipalName))]
        [DataRow(typeof(KrbTicket), "EncryptedPart", typeof(KrbEncryptedData))]
        [DataRow(typeof(KrbEncTicketPart), "Flags", typeof(TicketFlags))]
        [DataRow(typeof(KrbEncTicketPart), "Key", typeof(KrbEncryptionKey))]
        [DataRow(typeof(KrbEncTicketPart), "CRealm", typeof(string))]
        [DataRow(typeof(KrbEncTicketPart), "CName", typeof(KrbPrincipalName))]
        [DataRow(typeof(KrbEncTicketPart), "Transited", typeof(KrbTransitedEncoding))]
        [DataRow(typeof(KrbEncTicketPart), "AuthTime", typeof(DateTimeOffset))]
        [DataRow(typeof(KrbEncTicketPart), "StartTime", typeof(DateTimeOffset?))]
        [DataRow(typeof(KrbEncTicketPart), "EndTime", typeof(DateTimeOffset))]
        [DataRow(typeof(KrbEncTicketPart), "RenewTill", typeof(DateTimeOffset?))]
        [DataRow(typeof(KrbEncTicketPart), "CAddr", typeof(KrbHostAddress[]))]
        [DataRow(typeof(KrbEncTicketPart), "AuthorizationData", typeof(KrbAuthorizationData[]))]
        [DataRow(typeof(KrbKdcReqBody), "EType", typeof(EncryptionType[]))]
        [DataRow(typeof(KrbKdcReqBody), "Nonce", typeof(int))]
        [DataRow(typeof(KrbKdcReqBody), "CName", typeof(KrbPrincipalName))]
        [DataRow(typeof(KrbPaData), "Type", typeof(PaDataType))]
        [DataRow(typeof(KrbPrincipalName), "Type", typeof(PrincipalNameType))]
        [DataRow(typeof(KrbPrincipalName), "Name", typeof(string[]))]
        [DataRow(typeof(KrbEncryptedData), "EType", typeof(EncryptionType))]
        [DataRow(typeof(KrbEncryptedData), "Cipher", typeof(ReadOnlyMemory<byte>))]
        [DataRow(typeof(KrbEncryptionKey), "EType", typeof(EncryptionType))]
        [DataRow(typeof(KrbEncryptionKey), "KeyValue", typeof(ReadOnlyMemory<byte>))]
        [DataRow(typeof(KrbChecksum), "Type", typeof(ChecksumType))]
        [DataRow(typeof(KrbChecksum), "Checksum", typeof(ReadOnlyMemory<byte>))]
        [DataRow(typeof(KrbHostAddress), "AddressType", typeof(AddressType))]
        [DataRow(typeof(KrbHostAddress), "Address", typeof(ReadOnlyMemory<byte>))]
        [DataRow(typeof(KrbError), "ErrorCode", typeof(KerberosErrorCode))]
        [DataRow(typeof(KrbError), "Realm", typeof(string))]
        [DataRow(typeof(KrbError), "EData", typeof(ReadOnlyMemory<byte>?))]
        [DataRow(typeof(KrbAuthorizationData), "Type", typeof(AuthorizationDataType))]
        [DataRow(typeof(KrbAuthorizationData), "Data", typeof(ReadOnlyMemory<byte>))]
        [DataRow(typeof(KrbETypeInfo2Entry), "EType", typeof(EncryptionType))]
        [DataRow(typeof(KrbETypeInfo2Entry), "Salt", typeof(string))]
        [DataRow(typeof(KrbLastReq), "Type", typeof(int))]
        [DataRow(typeof(KrbLastReq), "Value", typeof(DateTimeOffset))]
        public void PropertyExists_WithCorrectType(Type declaringType, string propertyName, Type expectedPropertyType)
        {
            var prop = declaringType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);

            Assert.IsNotNull(prop,
                $"{declaringType.Name}.{propertyName} property not found");
            Assert.AreEqual(expectedPropertyType, prop.PropertyType,
                $"{declaringType.Name}.{propertyName} type mismatch: expected {expectedPropertyType.Name}, got {prop.PropertyType.Name}");
        }

        // ────────────────────────────────────────────────────────
        // Enum property types (verify @cs-enum / @cs-flags-enum)
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbEncTicketPart), "Flags", typeof(TicketFlags))]
        [DataRow(typeof(KrbKdcReqBody), "KdcOptions", typeof(KdcOptions))]
        [DataRow(typeof(KrbPaData), "Type", typeof(PaDataType))]
        [DataRow(typeof(KrbEncryptedData), "EType", typeof(EncryptionType))]
        [DataRow(typeof(KrbEncryptionKey), "EType", typeof(EncryptionType))]
        [DataRow(typeof(KrbChecksum), "Type", typeof(ChecksumType))]
        [DataRow(typeof(KrbHostAddress), "AddressType", typeof(AddressType))]
        [DataRow(typeof(KrbError), "ErrorCode", typeof(KerberosErrorCode))]
        [DataRow(typeof(KrbAuthorizationData), "Type", typeof(AuthorizationDataType))]
        [DataRow(typeof(KrbPrincipalName), "Type", typeof(PrincipalNameType))]
        public void EnumProperties_HaveCorrectEnumType(Type declaringType, string propertyName, Type expectedEnumType)
        {
            var prop = declaringType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
            Assert.IsNotNull(prop, $"{declaringType.Name}.{propertyName} not found");

            var actualType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
            Assert.IsTrue(actualType.IsEnum || actualType == expectedEnumType,
                $"{declaringType.Name}.{propertyName}: expected enum type {expectedEnumType.Name}, got {actualType.Name}");
        }

        // ────────────────────────────────────────────────────────
        // Nullable OPTIONAL fields
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbEncTicketPart), "StartTime", true, DisplayName = "KerberosTime OPTIONAL → DateTimeOffset?")]
        [DataRow(typeof(KrbEncTicketPart), "RenewTill", true, DisplayName = "KerberosTime OPTIONAL → DateTimeOffset?")]
        [DataRow(typeof(KrbEncTicketPart), "AuthTime", false, DisplayName = "KerberosTime required → DateTimeOffset")]
        [DataRow(typeof(KrbError), "EData", true, DisplayName = "OCTET STRING OPTIONAL → ReadOnlyMemory<byte>?")]
        [DataRow(typeof(KrbEncTicketPart), "Flags", false, DisplayName = "TicketFlags (BitStringFlagsEnum) → not nullable")]
        [DataRow(typeof(KrbCredInfo), "Flags", true, DisplayName = "TicketFlags OPTIONAL (flags) → nullable")]
        public void OptionalField_NullabilityIsCorrect(Type declaringType, string propertyName, bool shouldBeNullable)
        {
            var prop = declaringType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
            Assert.IsNotNull(prop, $"{declaringType.Name}.{propertyName} not found");

            bool isNullable = Nullable.GetUnderlyingType(prop.PropertyType) != null;

            Assert.AreEqual(shouldBeNullable, isNullable,
                $"{declaringType.Name}.{propertyName}: nullable={isNullable}, expected={shouldBeNullable}");
        }

        // ────────────────────────────────────────────────────────
        // Collection wrapper types
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbMethodData), "MethodData", typeof(KrbPaData[]))]
        [DataRow(typeof(KrbETypeInfo2), "ETypeInfo", typeof(KrbETypeInfo2Entry[]))]
        [DataRow(typeof(KrbETypeList), "List", typeof(EncryptionType[]))]
        [DataRow(typeof(KrbAuthorizationDataSequence), "AuthorizationData", typeof(KrbAuthorizationData[]))]
        [DataRow(typeof(KrbPaAuthenticationSet), "AuthenticationSet", typeof(KrbPaAuthenticationSetElement[]))]
        public void CollectionWrapper_HasExpectedArrayProperty(Type wrapperType, string propertyName, Type expectedArrayType)
        {
            var prop = wrapperType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
            Assert.IsNotNull(prop,
                $"{wrapperType.Name}.{propertyName} not found");
            Assert.AreEqual(expectedArrayType, prop.PropertyType,
                $"{wrapperType.Name}.{propertyName}: expected {expectedArrayType.Name}, got {prop.PropertyType.Name}");
        }

        // ────────────────────────────────────────────────────────
        // Inherited APPLICATION-tagged types
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbAsReq), typeof(KrbKdcReq))]
        [DataRow(typeof(KrbTgsReq), typeof(KrbKdcReq))]
        [DataRow(typeof(KrbAsRep), typeof(KrbKdcRep))]
        [DataRow(typeof(KrbTgsRep), typeof(KrbKdcRep))]
        [DataRow(typeof(KrbEncAsRepPart), typeof(KrbEncKdcRepPart))]
        [DataRow(typeof(KrbEncTgsRepPart), typeof(KrbEncKdcRepPart))]
        public void InheritedType_HasCorrectBaseClass(Type derivedType, Type expectedBaseType)
        {
            Assert.AreEqual(expectedBaseType, derivedType.BaseType,
                $"{derivedType.Name} should inherit from {expectedBaseType.Name}");
        }

        // ────────────────────────────────────────────────────────
        // Encode/Decode methods exist
        // ────────────────────────────────────────────────────────

        [TestMethod]
        [DataRow(typeof(KrbTicket), true, DisplayName = "KrbTicket has APPLICATION tag")]
        [DataRow(typeof(KrbAsReq), true, DisplayName = "KrbAsReq has APPLICATION tag")]
        [DataRow(typeof(KrbAsRep), true, DisplayName = "KrbAsRep has APPLICATION tag")]
        [DataRow(typeof(KrbTgsReq), true, DisplayName = "KrbTgsReq has APPLICATION tag")]
        [DataRow(typeof(KrbTgsRep), true, DisplayName = "KrbTgsRep has APPLICATION tag")]
        [DataRow(typeof(KrbApReq), true, DisplayName = "KrbApReq has APPLICATION tag")]
        [DataRow(typeof(KrbApRep), true, DisplayName = "KrbApRep has APPLICATION tag")]
        [DataRow(typeof(KrbError), true, DisplayName = "KrbError has APPLICATION tag")]
        [DataRow(typeof(KrbCred), true, DisplayName = "KrbCred has APPLICATION tag")]
        [DataRow(typeof(KrbPriv), true, DisplayName = "KrbPriv has APPLICATION tag")]
        [DataRow(typeof(KrbKdcReqBody), false, DisplayName = "KrbKdcReqBody has no APPLICATION tag")]
        [DataRow(typeof(KrbPaData), false, DisplayName = "KrbPaData has no APPLICATION tag")]
        [DataRow(typeof(KrbChecksum), false, DisplayName = "KrbChecksum has no APPLICATION tag")]
        public void EncodeDecodeMethodsExist(Type type, bool hasApplicationTag)
        {
            if (hasApplicationTag)
            {
                // APPLICATION-tagged types have DecodeApplication and EncodeApplication
                var decodeApp = type.GetMethod("DecodeApplication",
                    BindingFlags.Public | BindingFlags.Static,
                    null,
                    new[] { typeof(ReadOnlyMemory<byte>) },
                    null);

                var encodeApp = type.GetMethod("EncodeApplication",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    Type.EmptyTypes,
                    null);

                Assert.IsNotNull(decodeApp, $"{type.Name} missing static DecodeApplication");
                Assert.IsNotNull(encodeApp, $"{type.Name} missing instance EncodeApplication");

                // APPLICATION tag static field
                var appTagField = type.GetField("ApplicationTag",
                    BindingFlags.NonPublic | BindingFlags.Static);
                Assert.IsNotNull(appTagField, $"{type.Name} missing static ApplicationTag field");
            }
            else
            {
                // Plain SEQUENCE types have Encode() and Decode methods
                var encode = type.GetMethod("Encode",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    Type.EmptyTypes,
                    null);
                Assert.IsNotNull(encode, $"{type.Name} missing instance Encode()");
            }
        }

        // ────────────────────────────────────────────────────────
        // EncryptedPaData field type (METHOD-DATA wrapper)
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void EncryptedPaData_IsKrbMethodData_NotArray()
        {
            var prop = typeof(KrbEncKdcRepPart).GetProperty("EncryptedPaData",
                BindingFlags.Public | BindingFlags.Instance);

            Assert.IsNotNull(prop, "KrbEncKdcRepPart.EncryptedPaData not found");
            Assert.AreEqual(typeof(KrbMethodData), prop.PropertyType,
                "EncryptedPaData should be KrbMethodData (wrapper class), not KrbPaData[]");
        }

        // ────────────────────────────────────────────────────────
        // NegTokenResp.State should use NegotiateState enum
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void NegTokenResp_State_IsNullableNegotiateState()
        {
            var prop = typeof(NegTokenResp).GetProperty("State",
                BindingFlags.Public | BindingFlags.Instance);

            Assert.IsNotNull(prop, "NegTokenResp.State not found");

            var underlying = Nullable.GetUnderlyingType(prop.PropertyType);
            Assert.IsNotNull(underlying, "NegTokenResp.State should be nullable");
            Assert.AreEqual(typeof(NegotiateState), underlying,
                "NegTokenResp.State should be NegotiateState?");
        }
    }
}
