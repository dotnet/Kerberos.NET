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
    public class EmitterTests
    {
        /// <summary>
        /// Parse, resolve, and emit a single type. Returns the generated C# source.
        /// </summary>
        private static string EmitSingle(string asnBody, string? targetClassName = null)
        {
            var input = $@"
-- @cs-prefix: Krb
-- @cs-namespace: Kerberos.NET.Entities
TestModule DEFINITIONS EXPLICIT TAGS ::= BEGIN
Dummy ::= INTEGER
{asnBody}
END
";
            var schema = AsnParser.Parse(input, out var diags);
            Assert.AreEqual(0, diags.Count, $"Parse errors: {string.Join("; ", diags)}");

            var types = TypeResolver.Resolve(schema);
            Assert.IsTrue(types.Count > 0, "No resolved types");

            ResolvedType target;
            if (targetClassName != null)
            {
                target = types.First(t => t.ClassName == targetClassName);
            }
            else
            {
                target = types.First();
            }

            return CSharpEmitter.Emit(target);
        }

        // ─── Sequence (no APPLICATION tag) ──────────────────────────

        [TestMethod]
        public void Emit_Sequence_GeneratesPartialClass()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,     -- @cs-name: Type @cs-enum: PaDataType
    padata-value [2] OCTET STRING -- @cs-name: Value
}");
            Assert.IsTrue(code.Contains("public partial class KrbPaData"), "Should be partial class");
            Assert.IsTrue(code.Contains("namespace Kerberos.NET.Entities"), "Should have namespace");
        }

        [TestMethod]
        public void Emit_Sequence_GeneratesProperties()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,     -- @cs-name: Type @cs-enum: PaDataType
    padata-value [2] OCTET STRING -- @cs-name: Value
}");
            Assert.IsTrue(code.Contains("public PaDataType Type { get; set; }"), "Should have Type property");
            Assert.IsTrue(code.Contains("public ReadOnlyMemory<byte> Value { get; set; }"), "Should have Value property");
        }

        [TestMethod]
        public void Emit_Sequence_GeneratesEncodeMethod()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,     -- @cs-name: Type @cs-enum: PaDataType
    padata-value [2] OCTET STRING -- @cs-name: Value
}");
            Assert.IsTrue(code.Contains("public ReadOnlyMemory<byte> Encode()"), "Should have Encode() method");
            Assert.IsTrue(code.Contains("internal void Encode(AsnWriter writer)"), "Should have Encode(writer) method");
        }

        [TestMethod]
        public void Emit_Sequence_GeneratesDecodeMethod()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,     -- @cs-name: Type @cs-enum: PaDataType
    padata-value [2] OCTET STRING -- @cs-name: Value
}");
            Assert.IsTrue(code.Contains("internal static void Decode<T>(AsnReader reader"), "Should have generic Decode");
        }

        // ─── Sequence (WITH APPLICATION tag) ────────────────────────

        [TestMethod]
        public void Emit_SequenceWithAppTag_HasApplicationTag()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbTicket
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno  [0] INTEGER (5),     -- @cs-name: TicketNumber @cs-type: int
    realm    [1] GeneralString
}");
            Assert.IsTrue(code.Contains("ApplicationTag"), "Should have ApplicationTag field");
            Assert.IsTrue(code.Contains("Application, 1"), "ApplicationTag should be APPLICATION 1");
        }

        [TestMethod]
        public void Emit_SequenceWithAppTag_HasEncodeDecodeApplication()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbTicket
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno  [0] INTEGER (5),     -- @cs-name: TicketNumber @cs-type: int
    realm    [1] GeneralString
}");
            Assert.IsTrue(code.Contains("EncodeApplication"), "Should have EncodeApplication method");
            Assert.IsTrue(code.Contains("DecodeApplication"), "Should have DecodeApplication method");
        }

        // ─── Obsolete aliases ───────────────────────────────────────

        [TestMethod]
        public void Emit_ObsoleteAlias_Generated()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbTicket
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno  [0] INTEGER (5),     -- @cs-name: TicketNumber @cs-type: int
    realm    [1] GeneralString
}");
            Assert.IsTrue(code.Contains("[Obsolete"), "Should have [Obsolete] attribute");
            Assert.IsTrue(code.Contains("TktVno"), "Should have TktVno alias");
            Assert.IsTrue(code.Contains("TicketNumber"), "Should have TicketNumber primary property");
        }

        [TestMethod]
        public void Emit_NoObsoleteAlias_WhenNamesMatch()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbSimple
MySimple ::= SEQUENCE {
    realm [0] GeneralString  -- @cs-name: Realm
}");
            // Realm matches ToPascalCase("realm"), so no obsolete alias
            Assert.IsFalse(code.Contains("[Obsolete"), "Should NOT have [Obsolete] when names match");
        }

        // ─── InheritedSequence ──────────────────────────────────────

        [TestMethod]
        public void Emit_InheritedSequence_GeneratesInheritance()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbKdcReq
KDC-REQ ::= SEQUENCE {
    pvno [1] INTEGER   -- @cs-name: ProtocolVersionNumber @cs-type: int
}

-- @cs-class: KrbAsReq
AS-REQ ::= [APPLICATION 10] KDC-REQ
", targetClassName: "KrbAsReq");
            Assert.IsTrue(code.Contains("class KrbAsReq : KrbKdcReq"), "Should inherit from KrbKdcReq");
            Assert.IsTrue(code.Contains("ApplicationTag"), "Should have ApplicationTag");
            Assert.IsTrue(code.Contains("Application, 10"), "ApplicationTag should be APPLICATION 10");
        }

        [TestMethod]
        public void Emit_InheritedSequence_HasDecodeApplication()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbKdcReq
KDC-REQ ::= SEQUENCE {
    pvno [1] INTEGER   -- @cs-name: ProtocolVersionNumber @cs-type: int
}

-- @cs-class: KrbAsReq
AS-REQ ::= [APPLICATION 10] KDC-REQ
", targetClassName: "KrbAsReq");
            Assert.IsTrue(code.Contains("DecodeApplication"), "Should have DecodeApplication");
            Assert.IsTrue(code.Contains("EncodeApplication"), "Should have EncodeApplication");
        }

        // ─── CollectionWrapper ──────────────────────────────────────

        [TestMethod]
        public void Emit_CollectionWrapper_GeneratesArrayProperty()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,
    padata-value [2] OCTET STRING
}

-- @cs-class: KrbMethodData
-- @cs-name: MethodData
METHOD-DATA ::= SEQUENCE OF PA-DATA
", targetClassName: "KrbMethodData");
            Assert.IsTrue(code.Contains("public partial class KrbMethodData"), "Should be partial class");
            Assert.IsTrue(code.Contains("KrbPaData[]"), "Should have array of KrbPaData");
            Assert.IsTrue(code.Contains("MethodData"), "Should have MethodData property name");
        }

        [TestMethod]
        public void Emit_CollectionWrapper_HasEncodeDecode()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbPaData
PA-DATA ::= SEQUENCE {
    padata-type  [1] INTEGER,
    padata-value [2] OCTET STRING
}

-- @cs-class: KrbMethodData
-- @cs-name: MethodData
METHOD-DATA ::= SEQUENCE OF PA-DATA
", targetClassName: "KrbMethodData");
            Assert.IsTrue(code.Contains("Encode("), "Should have Encode method");
            Assert.IsTrue(code.Contains("Decode("), "Should have Decode method");
        }

        // ─── CHOICE ─────────────────────────────────────────────────

        [TestMethod]
        public void Emit_Choice_GeneratesAlternativeProperties()
        {
            var code = EmitSingle(@"
MyChoice ::= CHOICE {
    optionA  [0] INTEGER,
    optionB  [1] OCTET STRING,
    optionC  [2] GeneralString
}");
            Assert.IsTrue(code.Contains("public partial class"), "Should be partial class");
            Assert.IsTrue(code.Contains("OptionA"), "Should have OptionA property");
            Assert.IsTrue(code.Contains("OptionB"), "Should have OptionB property");
            Assert.IsTrue(code.Contains("OptionC"), "Should have OptionC property");
        }

        [TestMethod]
        public void Emit_Choice_ValueTypesAreNullable()
        {
            var code = EmitSingle(@"
MyChoice ::= CHOICE {
    intVal  [0] INTEGER,
    strVal  [1] GeneralString
}");
            Assert.IsTrue(code.Contains("int?"), "INTEGER in CHOICE should be nullable");
        }

        // ─── Generated code is syntactically valid ──────────────────

        [TestMethod]
        public void Emit_Sequence_ContainsLicenseHeader()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbSimple
Simple ::= SEQUENCE {
    val [0] INTEGER  -- @cs-type: int
}");
            Assert.IsTrue(code.Contains("Licensed to The .NET Foundation"), "Should have license header");
        }

        [TestMethod]
        public void Emit_Sequence_ContainsUsings()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbSimple
Simple ::= SEQUENCE {
    val [0] INTEGER  -- @cs-type: int
}");
            Assert.IsTrue(code.Contains("using System"), "Should have using System");
            Assert.IsTrue(code.Contains("System.Security.Cryptography.Asn1"), "Should use Asn1 namespace");
        }

        // ─── Optional field encoding ────────────────────────────────

        [TestMethod]
        public void Emit_OptionalField_HasConditionalEncoding()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbWithOptional
WithOptional ::= SEQUENCE {
    required [0] INTEGER,           -- @cs-type: int
    optional [1] GeneralString OPTIONAL
}");
            // Optional string field should have conditional check before encoding
            Assert.IsTrue(code.Contains("Asn1Extension.HasValue(Optional)") || code.Contains("Optional != null"),
                "Optional field should have conditional check in Encode");
        }

        // ─── Extensibility marker ───────────────────────────────────

        [TestMethod]
        public void Emit_ExtensibleSequence_MarksExtensible()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbExtensible
Extensible ::= SEQUENCE {
    val [0] INTEGER,    -- @cs-type: int
    ...
}");
            // Extensible sequences should still produce valid code
            Assert.IsTrue(code.Contains("public partial class KrbExtensible"), "Should generate class");
            Assert.IsTrue(code.Contains("Encode("), "Should have Encode method");
        }

        // ─── Inline collection field ────────────────────────────────

        [TestMethod]
        public void Emit_InlineSequenceOfField_GeneratesArrayProperty()
        {
            var code = EmitSingle(@"
-- @cs-class: KrbWithArray
WithArray ::= SEQUENCE {
    items [0] SEQUENCE OF INTEGER   -- @cs-type: int
}");
            Assert.IsTrue(code.Contains("int[]"), "Inline SEQUENCE OF INTEGER should produce int[]");
        }

        // ─── Full pipeline smoke test with real schema snippet ──────

        [TestMethod]
        public void FullPipeline_KerberosTicketSnippet()
        {
            var input = @"
-- @cs-prefix: Krb
-- @cs-namespace: Kerberos.NET.Entities
KerberosV5 DEFINITIONS EXPLICIT TAGS ::= BEGIN

KerberosString  ::= GeneralString
Realm           ::= KerberosString

-- @cs-class: KrbPrincipalName
PrincipalName ::= SEQUENCE {
    name-type   [0] INTEGER,    -- @cs-name: Type @cs-enum: PrincipalNameType
    name-string [1] SEQUENCE OF KerberosString  -- @cs-name: Name
}

-- @cs-class: KrbEncryptedData
EncryptedData ::= SEQUENCE {
    etype   [0] INTEGER,              -- @cs-name: EType @cs-enum: EncryptionType
    kvno    [1] INTEGER OPTIONAL,     -- @cs-name: KeyVersionNumber @cs-type: int
    cipher  [2] OCTET STRING          -- @cs-name: Cipher
}

-- @cs-class: KrbTicket
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno  [0] INTEGER (5),         -- @cs-name: TicketNumber @cs-type: int
    realm    [1] Realm,
    sname    [2] PrincipalName,       -- @cs-name: SName
    enc-part [3] EncryptedData        -- @cs-name: EncryptedPart
}

-- @cs-class: KrbAsReq
AS-REQ ::= [APPLICATION 10] Ticket

END
";
            var schema = AsnParser.Parse(input, out var diags);
            Assert.AreEqual(0, diags.Count, $"Parse diagnostics: {string.Join("; ", diags)}");

            var types = TypeResolver.Resolve(schema);

            // Should resolve: KrbPrincipalName, KrbEncryptedData, KrbTicket, KrbAsReq
            // Aliases (KerberosString, Realm) should NOT be in the resolved list
            Assert.IsFalse(types.Any(t => t.ClassName.Contains("Realm")));
            Assert.IsFalse(types.Any(t => t.ClassName.Contains("KerberosString")));

            var ticket = types.First(t => t.ClassName == "KrbTicket");
            Assert.AreEqual(ResolvedTypeKind.Sequence, ticket.Kind);
            Assert.AreEqual(1, ticket.ApplicationTag);

            var asReq = types.First(t => t.ClassName == "KrbAsReq");
            Assert.AreEqual(ResolvedTypeKind.InheritedSequence, asReq.Kind);
            Assert.AreEqual("KrbTicket", asReq.BaseClassName);

            // Emit each type and verify they all produce valid output
            foreach (var type in types)
            {
                var code = CSharpEmitter.Emit(type);
                Assert.IsTrue(code.Length > 0, $"Empty output for {type.ClassName}");
                Assert.IsTrue(code.Contains($"partial class {type.ClassName}"),
                    $"Missing partial class declaration for {type.ClassName}");
            }
        }

        // ─── Real schema integration test ───────────────────────────

        [TestMethod]
        public void FullPipeline_RealKerberosSchema_NoDiagnostics()
        {
            // Parse the actual kerberos.asn and kerberos-extensions.asn files
            var schemaPath = System.IO.Path.GetFullPath(
                System.IO.Path.Combine(System.AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "Kerberos.NET", "kerberos.asn"));
            var extPath = System.IO.Path.GetFullPath(
                System.IO.Path.Combine(System.AppContext.BaseDirectory, "..", "..", "..", "..", "..",
                    "Kerberos.NET", "kerberos-extensions.asn"));

            if (!System.IO.File.Exists(schemaPath))
            {
                Assert.Inconclusive($"Schema file not found at {schemaPath}");
                return;
            }

            var mainSchema = System.IO.File.ReadAllText(schemaPath);
            var extSchema = System.IO.File.Exists(extPath) ? System.IO.File.ReadAllText(extPath) : "";

            var combined = mainSchema + "\n" + extSchema;
            var schema = AsnParser.Parse(combined, out var diags);
            Assert.AreEqual(0, diags.Count,
                $"Real schema produced {diags.Count} diagnostics:\n{string.Join("\n", diags.Take(10))}");

            var types = TypeResolver.Resolve(schema);
            Assert.IsTrue(types.Count > 50, $"Expected 50+ types, got {types.Count}");

            // Emit all types — none should throw
            foreach (var type in types)
            {
                var code = CSharpEmitter.Emit(type);
                Assert.IsTrue(code.Length > 100,
                    $"Suspiciously short output ({code.Length} chars) for {type.ClassName}");
            }
        }
    }
}
