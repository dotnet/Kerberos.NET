// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace Kerberos.NET.Asn1SourceGenerator.Model
{
    /// <summary>
    /// Root container for all parsed ASN.1 modules from one or more .asn files.
    /// </summary>
    public class AsnSchema
    {
        public List<AsnModule> Modules { get; } = new List<AsnModule>();
    }

    /// <summary>
    /// Represents a single ASN.1 MODULE DEFINITIONS block.
    /// </summary>
    public class AsnModule
    {
        public string Name { get; set; } = "";
        public AsnTagDefault TagDefault { get; set; } = AsnTagDefault.Explicit;
        public List<AsnImport> Imports { get; } = new List<AsnImport>();
        public List<AsnTypeAssignment> TypeAssignments { get; } = new List<AsnTypeAssignment>();
        public List<AsnValueAssignment> ValueAssignments { get; } = new List<AsnValueAssignment>();
        public AsnModuleAnnotations Annotations { get; set; } = new AsnModuleAnnotations();
    }

    public enum AsnTagDefault
    {
        Explicit,
        Implicit,
        Automatic
    }

    public class AsnImport
    {
        public List<string> Symbols { get; } = new List<string>();
        public string FromModule { get; set; } = "";
    }

    /// <summary>
    /// A value assignment like: pa-pk-as-req INTEGER ::= 16
    /// These are skipped during code generation but preserved during parsing.
    /// </summary>
    public class AsnValueAssignment
    {
        public string Name { get; set; } = "";
        public string TypeName { get; set; } = "";
        public string Value { get; set; } = "";
    }

    /// <summary>
    /// A type assignment: TypeName ::= [tags] TypeBody
    /// </summary>
    public class AsnTypeAssignment
    {
        public string Name { get; set; } = "";
        public AsnType Type { get; set; } = null!;
        public AsnTypeAnnotations Annotations { get; set; } = new AsnTypeAnnotations();
    }

    // ─── ASN.1 Type Hierarchy ────────────────────────────────────────

    /// <summary>
    /// Base class for all ASN.1 types.
    /// </summary>
    public abstract class AsnType
    {
        /// <summary>
        /// Outer tag applied to this type, e.g., [APPLICATION 1] or [0].
        /// Null means no explicit outer tag.
        /// </summary>
        public AsnTag? Tag { get; set; }
    }

    /// <summary>
    /// SEQUENCE { field1, field2, ... }
    /// </summary>
    public class AsnSequenceType : AsnType
    {
        public List<AsnField> Fields { get; } = new List<AsnField>();
        public bool Extensible { get; set; }
    }

    /// <summary>
    /// CHOICE { alt1, alt2, ... }
    /// </summary>
    public class AsnChoiceType : AsnType
    {
        public List<AsnField> Alternatives { get; } = new List<AsnField>();
        public bool Extensible { get; set; }
    }

    /// <summary>
    /// SEQUENCE OF innerType or SET OF innerType.
    /// </summary>
    public class AsnCollectionType : AsnType
    {
        public bool IsSetOf { get; set; }
        public AsnType ElementType { get; set; } = null!;
        public AsnSizeConstraint? SizeConstraint { get; set; }
    }

    /// <summary>
    /// A reference to another named type (e.g., Realm, KerberosTime, PrincipalName).
    /// </summary>
    public class AsnReferencedType : AsnType
    {
        public string ReferencedName { get; set; } = "";
    }

    /// <summary>
    /// A tagged alias: AS-REQ ::= [APPLICATION 10] KDC-REQ
    /// Preserved as a distinct node so the emitter can generate inheritance.
    /// </summary>
    public class AsnTaggedTypeAlias : AsnType
    {
        public string ReferencedName { get; set; } = "";
    }

    /// <summary>
    /// A simple type alias: Realm ::= KerberosString
    /// </summary>
    public class AsnTypeAlias : AsnType
    {
        public string ReferencedName { get; set; } = "";
    }

    /// <summary>
    /// Primitive ASN.1 types: INTEGER, OCTET STRING, BIT STRING, BOOLEAN, etc.
    /// </summary>
    public class AsnPrimitiveType : AsnType
    {
        public AsnPrimitiveKind Kind { get; set; }
        public AsnConstraint? Constraint { get; set; }

        /// <summary>
        /// For ENUMERATED types, the named values.
        /// For BIT STRING with named bits, the named bits.
        /// </summary>
        public List<AsnNamedValue>? NamedValues { get; set; }
    }

    public enum AsnPrimitiveKind
    {
        Boolean,
        Integer,
        BitString,
        OctetString,
        ObjectIdentifier,
        Enumerated,
        Null,
        // String types
        UTF8String,
        PrintableString,
        IA5String,
        GeneralString,
        VisibleString,
        T61String,
        BMPString,
        // Time types
        GeneralizedTime,
        UtcTime,
        // Special
        Any
    }

    public class AsnNamedValue
    {
        public string Name { get; set; } = "";
        public int Value { get; set; }
    }

    /// <summary>
    /// ANY or ANY DEFINED BY fieldName
    /// </summary>
    public class AsnAnyType : AsnType
    {
        public string? DefinedBy { get; set; }
    }

    // ─── Fields ──────────────────────────────────────────────────────

    /// <summary>
    /// A field within a SEQUENCE or alternative in a CHOICE.
    /// </summary>
    public class AsnField
    {
        public string Name { get; set; } = "";
        public AsnType Type { get; set; } = null!;
        public bool Optional { get; set; }
        public bool HasDefault { get; set; }
        public string? DefaultValue { get; set; }
        public AsnFieldAnnotations Annotations { get; set; } = new AsnFieldAnnotations();
    }

    // ─── Tags ────────────────────────────────────────────────────────

    public class AsnTag
    {
        public AsnTagClass Class { get; set; } = AsnTagClass.ContextSpecific;
        public int Number { get; set; }
        public AsnTagMode? Mode { get; set; }
    }

    public enum AsnTagClass
    {
        Universal,
        Application,
        ContextSpecific,
        Private
    }

    public enum AsnTagMode
    {
        Explicit,
        Implicit
    }

    // ─── Constraints ─────────────────────────────────────────────────

    public abstract class AsnConstraint { }

    public class AsnValueConstraint : AsnConstraint
    {
        public long? MinValue { get; set; }
        public long? MaxValue { get; set; }
        public bool MaxIsMax { get; set; }
    }

    public class AsnSizeConstraint : AsnConstraint
    {
        public long? MinSize { get; set; }
        public long? MaxSize { get; set; }
        public bool MaxIsMax { get; set; }
    }

    // ─── Annotations (C# codegen metadata in ASN.1 comments) ────────

    public class AsnModuleAnnotations
    {
        public string? Namespace { get; set; }
        public string? ClassPrefix { get; set; }
    }

    public class AsnTypeAnnotations
    {
        /// <summary>Override the generated class name entirely.</summary>
        public string? ClassName { get; set; }

        /// <summary>Override the namespace for this type only.</summary>
        public string? Namespace { get; set; }

        /// <summary>For collection wrappers: override the wrapper property name.</summary>
        public string? PropertyName { get; set; }

        /// <summary>For collection wrappers: override the element enum type.</summary>
        public string? EnumType { get; set; }
    }

    public class AsnFieldAnnotations
    {
        /// <summary>Override the generated property name.</summary>
        public string? PropertyName { get; set; }

        /// <summary>C# backing type for INTEGER fields: int, byte, long.</summary>
        public string? BackingType { get; set; }

        /// <summary>Map INTEGER to this C# enum type.</summary>
        public string? EnumType { get; set; }

        /// <summary>Map BIT STRING to this C# flags enum type.</summary>
        public string? FlagsEnumType { get; set; }

        /// <summary>Default DER initialization bytes (hex string).</summary>
        public string? DefaultDerInit { get; set; }
    }
}
