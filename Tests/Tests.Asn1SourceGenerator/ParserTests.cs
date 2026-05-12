// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using Kerberos.NET.Asn1SourceGenerator.Model;
using Kerberos.NET.Asn1SourceGenerator.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Asn1SourceGenerator
{
    [TestClass]
    public class ParserTests
    {
        private static AsnSchema ParseSingle(string body)
        {
            var input = $"TestModule DEFINITIONS EXPLICIT TAGS ::= BEGIN\n{body}\nEND\n";
            var schema = AsnParser.Parse(input, out var diags);
            Assert.AreEqual(0, diags.Count, $"Unexpected diagnostics: {string.Join("; ", diags)}");
            return schema;
        }

        // ─── Module structure ───────────────────────────────────────

        [TestMethod]
        public void Parse_EmptyModule()
        {
            var schema = ParseSingle("");
            Assert.AreEqual(1, schema.Modules.Count);
            Assert.AreEqual("TestModule", schema.Modules[0].Name);
            Assert.AreEqual(AsnTagDefault.Explicit, schema.Modules[0].TagDefault);
        }

        [TestMethod]
        public void Parse_ImplicitTagsModule()
        {
            var input = "ImplMod DEFINITIONS IMPLICIT TAGS ::= BEGIN\nEND\n";
            var schema = AsnParser.Parse(input);
            Assert.AreEqual(AsnTagDefault.Implicit, schema.Modules[0].TagDefault);
        }

        [TestMethod]
        public void Parse_MultipleModules()
        {
            var input = @"
ModA DEFINITIONS EXPLICIT TAGS ::= BEGIN
    TypeA ::= INTEGER
END

ModB DEFINITIONS IMPLICIT TAGS ::= BEGIN
    TypeB ::= BOOLEAN
END
";
            var schema = AsnParser.Parse(input);
            Assert.AreEqual(2, schema.Modules.Count);
            Assert.AreEqual("ModA", schema.Modules[0].Name);
            Assert.AreEqual("ModB", schema.Modules[1].Name);
        }

        // ─── Type aliases ───────────────────────────────────────────

        [TestMethod]
        public void Parse_SimpleAlias()
        {
            var schema = ParseSingle("Realm ::= GeneralString");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.AreEqual("Realm", ta.Name);
            // GeneralString is a primitive keyword, so this is parsed as AsnPrimitiveType
            Assert.IsInstanceOfType(ta.Type, typeof(AsnPrimitiveType));
            Assert.AreEqual(AsnPrimitiveKind.GeneralString, ((AsnPrimitiveType)ta.Type).Kind);
        }

        [TestMethod]
        public void Parse_PrimitiveType()
        {
            var schema = ParseSingle("Counter ::= INTEGER");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.IsInstanceOfType(ta.Type, typeof(AsnPrimitiveType));
            Assert.AreEqual(AsnPrimitiveKind.Integer, ((AsnPrimitiveType)ta.Type).Kind);
        }

        // ─── Value assignments ──────────────────────────────────────

        [TestMethod]
        public void Parse_ValueAssignment()
        {
            var schema = ParseSingle("pvno INTEGER ::= 5");
            var va = schema.Modules[0].ValueAssignments.Single();
            Assert.AreEqual("pvno", va.Name);
            Assert.AreEqual("5", va.Value);
        }

        // ─── SEQUENCE ───────────────────────────────────────────────

        [TestMethod]
        public void Parse_SimpleSequence()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    name    [0] GeneralString,
    value   [1] INTEGER
}");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.IsInstanceOfType(ta.Type, typeof(AsnSequenceType));
            var seq = (AsnSequenceType)ta.Type;
            Assert.AreEqual(2, seq.Fields.Count);
            Assert.AreEqual("name", seq.Fields[0].Name);
            Assert.AreEqual("value", seq.Fields[1].Name);
        }

        [TestMethod]
        public void Parse_SequenceField_Tags()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    field0  [0] INTEGER,
    field3  [3] OCTET STRING
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.AreEqual(0, seq.Fields[0].Type.Tag!.Number);
            Assert.AreEqual(3, seq.Fields[1].Type.Tag!.Number);
        }

        [TestMethod]
        public void Parse_SequenceField_OptionalAndDefault()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    required    [0] INTEGER,
    optional    [1] GeneralString OPTIONAL,
    defaulted   [2] INTEGER DEFAULT 5
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.IsFalse(seq.Fields[0].Optional);
            Assert.IsTrue(seq.Fields[1].Optional);
            Assert.IsTrue(seq.Fields[2].HasDefault);
        }

        [TestMethod]
        public void Parse_SequenceWithExtensibilityMarker()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    field1  [0] INTEGER,
    ...
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.IsTrue(seq.Extensible);
            Assert.AreEqual(1, seq.Fields.Count);
        }

        [TestMethod]
        public void Parse_SequenceWithApplicationTag()
        {
            var schema = ParseSingle(@"
Ticket ::= [APPLICATION 1] SEQUENCE {
    tkt-vno  [0] INTEGER (5),
    realm    [1] GeneralString
}");
            var ta = schema.Modules[0].TypeAssignments.Single();
            var seq = (AsnSequenceType)ta.Type;
            Assert.IsNotNull(seq.Tag);
            Assert.AreEqual(AsnTagClass.Application, seq.Tag!.Class);
            Assert.AreEqual(1, seq.Tag.Number);
            Assert.AreEqual(2, seq.Fields.Count);
        }

        // ─── CHOICE ─────────────────────────────────────────────────

        [TestMethod]
        public void Parse_Choice()
        {
            var schema = ParseSingle(@"
MyChoice ::= CHOICE {
    optionA  [0] INTEGER,
    optionB  [1] OCTET STRING,
    optionC  [2] GeneralString
}");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.IsInstanceOfType(ta.Type, typeof(AsnChoiceType));
            var choice = (AsnChoiceType)ta.Type;
            Assert.AreEqual(3, choice.Alternatives.Count);
            Assert.AreEqual("optionA", choice.Alternatives[0].Name);
        }

        // ─── SEQUENCE OF / SET OF ───────────────────────────────────

        [TestMethod]
        public void Parse_SequenceOf()
        {
            var schema = ParseSingle("MyList ::= SEQUENCE OF INTEGER");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.IsInstanceOfType(ta.Type, typeof(AsnCollectionType));
            var coll = (AsnCollectionType)ta.Type;
            Assert.IsFalse(coll.IsSetOf);
            Assert.IsInstanceOfType(coll.ElementType, typeof(AsnPrimitiveType));
        }

        [TestMethod]
        public void Parse_SetOf()
        {
            var schema = ParseSingle("MySet ::= SET OF GeneralString");
            var coll = (AsnCollectionType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.IsTrue(coll.IsSetOf);
        }

        [TestMethod]
        public void Parse_SequenceOfReference()
        {
            var schema = ParseSingle("HostAddresses ::= SEQUENCE OF HostAddress");
            var coll = (AsnCollectionType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.IsInstanceOfType(coll.ElementType, typeof(AsnReferencedType));
            Assert.AreEqual("HostAddress", ((AsnReferencedType)coll.ElementType).ReferencedName);
        }

        // ─── Tagged type alias (InheritedSequence) ──────────────────

        [TestMethod]
        public void Parse_TaggedTypeAlias()
        {
            var schema = ParseSingle("AS-REQ ::= [APPLICATION 10] KDC-REQ");
            var ta = schema.Modules[0].TypeAssignments.Single();
            Assert.IsInstanceOfType(ta.Type, typeof(AsnTaggedTypeAlias));
            var alias = (AsnTaggedTypeAlias)ta.Type;
            Assert.AreEqual("KDC-REQ", alias.ReferencedName);
            Assert.IsNotNull(alias.Tag);
            Assert.AreEqual(AsnTagClass.Application, alias.Tag!.Class);
            Assert.AreEqual(10, alias.Tag.Number);
        }

        // ─── IMPORTS ────────────────────────────────────────────────

        [TestMethod]
        public void Parse_Imports()
        {
            var input = @"
TestModule DEFINITIONS EXPLICIT TAGS ::= BEGIN
    IMPORTS
        AlgorithmIdentifier FROM AuthenticationFramework;
    TypeA ::= INTEGER
END
";
            var schema = AsnParser.Parse(input);
            var module = schema.Modules[0];
            Assert.AreEqual(1, module.Imports.Count);
            Assert.AreEqual("AuthenticationFramework", module.Imports[0].FromModule);
            Assert.IsTrue(module.Imports[0].Symbols.Contains("AlgorithmIdentifier"));
        }

        // ─── Annotations ────────────────────────────────────────────

        [TestMethod]
        public void Parse_TypeAnnotation_ClassName()
        {
            // Note: annotations right after BEGIN are consumed as module-level.
            // Place a dummy type first so the annotation applies to the target type.
            var schema = ParseSingle(@"
Dummy ::= INTEGER

-- @cs-class: KrbTicket
Ticket ::= SEQUENCE {
    realm [0] GeneralString
}");
            var ta = schema.Modules[0].TypeAssignments.First(t => t.Name == "Ticket");
            Assert.AreEqual("KrbTicket", ta.Annotations.ClassName);
        }

        [TestMethod]
        public void Parse_TypeAnnotation_Namespace()
        {
            var schema = ParseSingle(@"
Dummy ::= INTEGER

-- @cs-namespace: Custom.Namespace
-- @cs-class: MyType
MyType ::= SEQUENCE {
    field [0] INTEGER
}");
            var ta = schema.Modules[0].TypeAssignments.First(t => t.Name == "MyType");
            Assert.AreEqual("Custom.Namespace", ta.Annotations.Namespace);
        }

        [TestMethod]
        public void Parse_FieldAnnotation_Name()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    tkt-vno [0] INTEGER       -- @cs-name: TicketNumber @cs-type: int
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.AreEqual("TicketNumber", seq.Fields[0].Annotations.PropertyName);
            Assert.AreEqual("int", seq.Fields[0].Annotations.BackingType);
        }

        [TestMethod]
        public void Parse_FieldAnnotation_Enum()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    etype [0] INTEGER          -- @cs-enum: EncryptionType
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.AreEqual("EncryptionType", seq.Fields[0].Annotations.EnumType);
        }

        [TestMethod]
        public void Parse_FieldAnnotation_FlagsEnum()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    flags [0] BIT STRING       -- @cs-flags-enum: TicketFlags
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.AreEqual("TicketFlags", seq.Fields[0].Annotations.FlagsEnumType);
        }

        [TestMethod]
        public void Parse_ModuleAnnotation_Prefix()
        {
            var input = @"
-- @cs-prefix: Krb
-- @cs-namespace: Kerberos.NET.Entities
TestModule DEFINITIONS EXPLICIT TAGS ::= BEGIN
    MyType ::= INTEGER
END
";
            var schema = AsnParser.Parse(input);
            Assert.AreEqual("Krb", schema.Modules[0].Annotations.ClassPrefix);
            Assert.AreEqual("Kerberos.NET.Entities", schema.Modules[0].Annotations.Namespace);
        }

        // ─── Constraint parsing ─────────────────────────────────────

        [TestMethod]
        public void Parse_IntegerWithFixedValue()
        {
            var schema = ParseSingle("MySeq ::= SEQUENCE { vno [0] INTEGER (5) }");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            var prim = (AsnPrimitiveType)seq.Fields[0].Type;
            Assert.IsInstanceOfType(prim, typeof(AsnPrimitiveType));
        }

        // ─── IMPLICIT tag mode on fields ────────────────────────────

        [TestMethod]
        public void Parse_ExplicitImplicitFieldTags()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    expl [0] EXPLICIT INTEGER,
    impl [1] IMPLICIT OCTET STRING
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.AreEqual(AsnTagMode.Explicit, seq.Fields[0].Type.Tag!.Mode);
            Assert.AreEqual(AsnTagMode.Implicit, seq.Fields[1].Type.Tag!.Mode);
        }

        // ─── Parser recovery ────────────────────────────────────────

        [TestMethod]
        public void Parse_RecoverFromBadAssignment()
        {
            var input = @"
TestModule DEFINITIONS EXPLICIT TAGS ::= BEGIN
    BadType ::= WEIRD STUFF THAT DOESNT PARSE
    GoodType ::= INTEGER
END
";
            var schema = AsnParser.Parse(input, out var diags);
            // Should recover and parse GoodType
            Assert.IsTrue(diags.Count > 0, "Should have diagnostics for bad assignment");
            Assert.IsTrue(schema.Modules[0].TypeAssignments.Any(t => t.Name == "GoodType"),
                "Should have recovered and parsed GoodType");
        }

        // ─── ENUMERATED ─────────────────────────────────────────────

        [TestMethod]
        public void Parse_Enumerated()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    state [0] ENUMERATED { accept(0), reject(2) } OPTIONAL  -- @cs-enum: MyState
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            var field = seq.Fields[0];
            Assert.IsTrue(field.Optional);
            Assert.AreEqual("MyState", field.Annotations.EnumType);
            Assert.IsInstanceOfType(field.Type, typeof(AsnPrimitiveType));
            var prim = (AsnPrimitiveType)field.Type;
            Assert.AreEqual(AsnPrimitiveKind.Enumerated, prim.Kind);
        }

        // ─── Inline SEQUENCE OF in field ────────────────────────────

        [TestMethod]
        public void Parse_InlineSequenceOfField()
        {
            var schema = ParseSingle(@"
MySeq ::= SEQUENCE {
    items [0] SEQUENCE OF INTEGER
}");
            var seq = (AsnSequenceType)schema.Modules[0].TypeAssignments.Single().Type;
            Assert.IsInstanceOfType(seq.Fields[0].Type, typeof(AsnCollectionType));
        }
    }
}
