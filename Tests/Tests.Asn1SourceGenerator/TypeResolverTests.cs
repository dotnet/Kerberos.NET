// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Asn1SourceGenerator.Emit;
using Kerberos.NET.Asn1SourceGenerator.Model;
using Kerberos.NET.Asn1SourceGenerator.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Asn1SourceGenerator
{
    [TestClass]
    public class TypeResolverTests
    {
        private static List<ResolvedType> ResolveSchema(string body, string prefix = "Krb",
            string ns = "Kerberos.NET.Entities", AsnTagDefault tagDefault = AsnTagDefault.Explicit)
        {
            var tagKeyword = tagDefault == AsnTagDefault.Implicit ? "IMPLICIT" : "EXPLICIT";
            var input = $@"
-- @cs-prefix: {prefix}
-- @cs-namespace: {ns}
TestModule DEFINITIONS {tagKeyword} TAGS ::= BEGIN
Dummy ::= INTEGER
{body}
END
";
            var schema = AsnParser.Parse(input, out var diags);
            Assert.AreEqual(0, diags.Count, $"Parse errors: {string.Join("; ", diags)}");
            return TypeResolver.Resolve(schema);
        }

        // ─── Class naming ───────────────────────────────────────────

        [TestMethod]
        public void Resolve_ClassNaming_PrefixPlusPascalCase()
        {
            var types = ResolveSchema(@"
KDC-REQ ::= SEQUENCE {
    pvno [1] INTEGER
}");
            var t = types.Single();
            Assert.AreEqual("KrbKdcReq", t.ClassName);
            Assert.AreEqual("Kerberos.NET.Entities", t.Namespace);
        }

        [TestMethod]
        public void Resolve_ClassNaming_AnnotationOverridesDefault()
        {
            var types = ResolveSchema(@"
Dummy ::= INTEGER

-- @cs-class: KrbCustomName
KDC-REQ ::= SEQUENCE {
    pvno [1] INTEGER
}");
            var t = types.Single();
            Assert.AreEqual("KrbCustomName", t.ClassName);
        }

        // ─── Type aliases (transparent) ─────────────────────────────

        [TestMethod]
        public void Resolve_TypeAlias_Skipped()
        {
            var types = ResolveSchema("Realm ::= GeneralString");
            Assert.AreEqual(0, types.Count, "Pure type aliases should not be emitted");
        }

        [TestMethod]
        public void Resolve_PrimitiveAlias_Skipped()
        {
            var types = ResolveSchema("KerberosFlags ::= BIT STRING");
            Assert.AreEqual(0, types.Count, "Primitive aliases should not be emitted");
        }

        // ─── SEQUENCE resolution ────────────────────────────────────

        [TestMethod]
        public void Resolve_Sequence_BasicFields()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    name    [0] GeneralString,
    value   [1] INTEGER
}");
            var t = types.Single();
            Assert.AreEqual(ResolvedTypeKind.Sequence, t.Kind);
            Assert.AreEqual(2, t.Fields.Count);
            Assert.AreEqual("Name", t.Fields[0].PropertyName);
            Assert.AreEqual("string", t.Fields[0].CSharpType);
            Assert.AreEqual("Value", t.Fields[1].PropertyName);
            Assert.AreEqual("int", t.Fields[1].CSharpType);
        }

        [TestMethod]
        public void Resolve_Sequence_WithApplicationTag()
        {
            var types = ResolveSchema(@"
Ticket ::= [APPLICATION 1] SEQUENCE {
    realm [1] GeneralString
}");
            var t = types.Single();
            Assert.AreEqual(ResolvedTypeKind.Sequence, t.Kind);
            Assert.AreEqual(1, t.ApplicationTag);
        }

        // ─── Field type mapping ─────────────────────────────────────

        [TestMethod]
        [DataRow("INTEGER", "int", FieldKind.Integer)]
        [DataRow("BOOLEAN", "bool", FieldKind.Boolean)]
        [DataRow("OCTET STRING", "ReadOnlyMemory<byte>", FieldKind.OctetString)]
        [DataRow("BIT STRING", "ReadOnlyMemory<byte>", FieldKind.BitString)]
        [DataRow("GeneralString", "string", FieldKind.GeneralString)]
        [DataRow("UTF8String", "string", FieldKind.UTF8String)]
        [DataRow("IA5String", "string", FieldKind.IA5String)]
        [DataRow("GeneralizedTime", "DateTimeOffset", FieldKind.GeneralizedTime)]
        [DataRow("OBJECT IDENTIFIER", "Oid", FieldKind.ObjectIdentifier)]
        public void Resolve_PrimitiveFieldTypes(string asnType, string expectedCSharp, FieldKind expectedKind)
        {
            var types = ResolveSchema($@"
MySeq ::= SEQUENCE {{
    field [0] {asnType}
}}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual(expectedCSharp, field.CSharpType);
            Assert.AreEqual(expectedKind, field.Encoding.Kind);
        }

        // ─── Annotations → enum mapping ─────────────────────────────

        [TestMethod]
        public void Resolve_IntegerEnum()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    etype [0] INTEGER        -- @cs-enum: EncryptionType
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("EncryptionType", field.CSharpType);
            Assert.AreEqual(FieldKind.IntegerEnum, field.Encoding.Kind);
            Assert.AreEqual("EncryptionType", field.Encoding.EnumType);
        }

        [TestMethod]
        public void Resolve_FlagsEnum()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    flags [0] BIT STRING     -- @cs-flags-enum: TicketFlags
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("TicketFlags", field.CSharpType);
            Assert.AreEqual(FieldKind.BitStringFlagsEnum, field.Encoding.Kind);
            Assert.IsTrue(field.Encoding.IsFlagsEnum);
        }

        [TestMethod]
        public void Resolve_Enumerated_WithAnnotation()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    state [0] ENUMERATED { a(0), b(1) } OPTIONAL  -- @cs-enum: MyState
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("MyState?", field.CSharpType);
            Assert.AreEqual(FieldKind.Enumerated, field.Encoding.Kind);
        }

        // ─── Backing type overrides ─────────────────────────────────

        [TestMethod]
        public void Resolve_BackingType_Int()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    counter [0] INTEGER    -- @cs-type: int
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("int", field.CSharpType);
        }

        [TestMethod]
        public void Resolve_BackingType_BigInt()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    big [0] INTEGER    -- @cs-type: bigint
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("System.Numerics.BigInteger", field.CSharpType);
            Assert.AreEqual(FieldKind.BigInteger, field.Encoding.Kind);
        }

        // ─── Nullable OPTIONAL handling ─────────────────────────────

        [TestMethod]
        public void Resolve_Optional_IntIsNullable()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    val [0] INTEGER OPTIONAL   -- @cs-type: int
}");
            Assert.AreEqual("int?", types.Single().Fields.Single().CSharpType);
        }

        [TestMethod]
        public void Resolve_Optional_DateTimeOffsetIsNullable()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    time [0] GeneralizedTime OPTIONAL
}");
            Assert.AreEqual("DateTimeOffset?", types.Single().Fields.Single().CSharpType);
        }

        [TestMethod]
        public void Resolve_Optional_OctetStringIsNullable()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    data [0] OCTET STRING OPTIONAL
}");
            Assert.AreEqual("ReadOnlyMemory<byte>?", types.Single().Fields.Single().CSharpType);
        }

        [TestMethod]
        public void Resolve_Optional_StringIsNotAppendedNullable()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    name [0] GeneralString OPTIONAL
}");
            // Strings are reference types — no '?' suffix
            Assert.AreEqual("string", types.Single().Fields.Single().CSharpType);
        }

        [TestMethod]
        public void Resolve_Optional_FlagsEnumIsNullable()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    flags [0] BIT STRING OPTIONAL  -- @cs-flags-enum: MyFlags
}");
            Assert.AreEqual("MyFlags?", types.Single().Fields.Single().CSharpType);
        }

        // ─── Obsolete alias generation ──────────────────────────────

        [TestMethod]
        public void Resolve_ObsoleteAlias_WhenNameDiffers()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    tkt-vno [0] INTEGER     -- @cs-name: TicketNumber @cs-type: int
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("TicketNumber", field.PropertyName);
            Assert.AreEqual("TktVno", field.ObsoleteAliasName);
        }

        [TestMethod]
        public void Resolve_NoObsoleteAlias_WhenNameMatches()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    realm [0] GeneralString  -- @cs-name: Realm
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("Realm", field.PropertyName);
            Assert.IsNull(field.ObsoleteAliasName);
        }

        // ─── Alias chain resolution ─────────────────────────────────

        [TestMethod]
        public void Resolve_AliasChain_PrimitiveThroughMultipleLevels()
        {
            var types = ResolveSchema(@"
KerberosString ::= GeneralString
Realm ::= KerberosString

MySeq ::= SEQUENCE {
    realm [0] Realm
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("string", field.CSharpType);
            Assert.AreEqual(FieldKind.GeneralString, field.Encoding.Kind);
        }

        [TestMethod]
        public void Resolve_AliasChain_FlagsEnumThroughAlias()
        {
            var types = ResolveSchema(@"
KerberosFlags ::= BIT STRING
KDCOptions ::= KerberosFlags

MySeq ::= SEQUENCE {
    opts [0] KDCOptions      -- @cs-flags-enum: KdcOptions
}");
            var field = types.Single().Fields.Single();
            Assert.AreEqual("KdcOptions", field.CSharpType);
            Assert.AreEqual(FieldKind.BitStringFlagsEnum, field.Encoding.Kind);
        }

        // ─── Collection resolution ──────────────────────────────────

        [TestMethod]
        public void Resolve_TransparentCollection_ResolvedToArray()
        {
            var types = ResolveSchema(@"
-- @cs-class: KrbHostAddress
HostAddress ::= SEQUENCE {
    addr-type [0] INTEGER,
    address   [1] OCTET STRING
}

HostAddresses ::= SEQUENCE OF HostAddress

MySeq ::= SEQUENCE {
    addresses [0] HostAddresses
}");
            // HostAddresses has no @cs-class, so it's transparent
            var mySeq = types.First(t => t.ClassName.Contains("MySeq"));
            var field = mySeq.Fields.Single();
            Assert.AreEqual("KrbHostAddress[]", field.CSharpType);
            Assert.IsTrue(field.IsCollection);
        }

        [TestMethod]
        public void Resolve_CollectionWrapper_WithAnnotation()
        {
            var types = ResolveSchema(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type [1] INTEGER,
    padata-value [2] OCTET STRING
}

-- @cs-class: KrbMethodData
-- @cs-name: MethodData
METHOD-DATA ::= SEQUENCE OF PA-DATA
");
            var wrapper = types.FirstOrDefault(t => t.ClassName == "KrbMethodData");
            Assert.IsNotNull(wrapper, "Collection with @cs-class should be emitted as wrapper");
            Assert.AreEqual(ResolvedTypeKind.CollectionWrapper, wrapper!.Kind);
            Assert.AreEqual(1, wrapper.Fields.Count);
            Assert.AreEqual("MethodData", wrapper.Fields[0].PropertyName);
            Assert.AreEqual("KrbPaData[]", wrapper.Fields[0].CSharpType);
        }

        // ─── InheritedSequence ──────────────────────────────────────

        [TestMethod]
        public void Resolve_InheritedSequence()
        {
            var types = ResolveSchema(@"
-- @cs-class: KrbKdcReq
KDC-REQ ::= SEQUENCE {
    pvno [1] INTEGER
}

-- @cs-class: KrbAsReq
AS-REQ ::= [APPLICATION 10] KDC-REQ
");
            var asReq = types.First(t => t.ClassName == "KrbAsReq");
            Assert.AreEqual(ResolvedTypeKind.InheritedSequence, asReq.Kind);
            Assert.AreEqual(10, asReq.ApplicationTag);
            Assert.AreEqual("KrbKdcReq", asReq.BaseClassName);
        }

        // ─── CHOICE resolution ──────────────────────────────────────

        [TestMethod]
        public void Resolve_Choice_AlternativesNullable()
        {
            var types = ResolveSchema(@"
MyChoice ::= CHOICE {
    intVal   [0] INTEGER,
    strVal   [1] GeneralString,
    timeVal  [2] GeneralizedTime
}");
            var t = types.Single();
            Assert.AreEqual(ResolvedTypeKind.Choice, t.Kind);
            Assert.IsTrue(t.IsChoice);

            // Value types should be nullable in CHOICE
            var intField = t.Fields.First(f => f.PropertyName == "IntVal");
            Assert.AreEqual("int?", intField.CSharpType);

            var timeField = t.Fields.First(f => f.PropertyName == "TimeVal");
            Assert.AreEqual("DateTimeOffset?", timeField.CSharpType);

            // Reference types should NOT have '?'
            var strField = t.Fields.First(f => f.PropertyName == "StrVal");
            Assert.AreEqual("string", strField.CSharpType);
        }

        // ─── Tag default (IMPLICIT vs EXPLICIT module) ──────────────

        [TestMethod]
        public void Resolve_ImplicitTagDefault_AffectsFieldsWithoutExplicitMode()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    field0 [0] INTEGER,
    field1 [1] EXPLICIT OCTET STRING
}", tagDefault: AsnTagDefault.Implicit);
            var fields = types.Single().Fields;

            // field0 has no mode specified → uses module default (IMPLICIT)
            Assert.IsTrue(fields[0].Encoding.IsImplicit);

            // field1 explicitly says EXPLICIT → overrides module default
            Assert.IsFalse(fields[1].Encoding.IsImplicit);
        }

        [TestMethod]
        public void Resolve_ExplicitTagDefault_FieldsAreExplicit()
        {
            var types = ResolveSchema(@"
MySeq ::= SEQUENCE {
    field0 [0] INTEGER,
    field1 [1] IMPLICIT OCTET STRING
}", tagDefault: AsnTagDefault.Explicit);
            var fields = types.Single().Fields;

            // field0 has no mode → uses module default (EXPLICIT)
            Assert.IsFalse(fields[0].Encoding.IsImplicit);

            // field1 explicitly says IMPLICIT → overrides module default
            Assert.IsTrue(fields[1].Encoding.IsImplicit);
        }

        // ─── ToPascalCase utility ───────────────────────────────────

        [TestMethod]
        [DataRow("tkt-vno", "TktVno")]
        [DataRow("KDC-REQ", "KdcReq")]
        [DataRow("AS-REQ", "AsReq")]
        [DataRow("enc-part", "EncPart")]
        [DataRow("pvno", "Pvno")]
        [DataRow("PA-DATA", "PaData")]
        [DataRow("e-text", "EText")]
        [DataRow("realm", "Realm")]
        public void ToPascalCase_Conversions(string input, string expected)
        {
            Assert.AreEqual(expected, TypeResolver.ToPascalCase(input));
        }

        // ─── Cross-module resolution ────────────────────────────────

        [TestMethod]
        public void Resolve_CrossModule_TypeReference()
        {
            var input = @"
-- @cs-prefix: Krb
-- @cs-namespace: Kerberos.NET.Entities
ModA DEFINITIONS EXPLICIT TAGS ::= BEGIN
    -- @cs-class: KrbInnerType
    InnerType ::= SEQUENCE {
        val [0] INTEGER
    }
END

-- @cs-prefix: Krb
-- @cs-namespace: Kerberos.NET.Entities
ModB DEFINITIONS EXPLICIT TAGS ::= BEGIN
    -- @cs-class: KrbOuterType
    OuterType ::= SEQUENCE {
        inner [0] InnerType
    }
END
";
            var schema = AsnParser.Parse(input, out var diags);
            Assert.AreEqual(0, diags.Count, string.Join("; ", diags));
            var types = TypeResolver.Resolve(schema);

            var outer = types.First(t => t.ClassName == "KrbOuterType");
            var field = outer.Fields.Single();
            Assert.AreEqual("KrbInnerType", field.CSharpType);
            Assert.AreEqual(FieldKind.CustomType, field.Encoding.Kind);
        }
    }
}
