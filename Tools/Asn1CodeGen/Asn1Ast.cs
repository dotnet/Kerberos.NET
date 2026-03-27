// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;

namespace Kerberos.NET.Asn1CodeGen
{
    public class Asn1Module
    {
        public string Name { get; set; }
        public string OidComponents { get; set; }
        public TagDefault TagDefault { get; set; } = TagDefault.Explicit;
        public List<Asn1Import> Imports { get; set; } = new();
        public List<Asn1TypeAssignment> TypeAssignments { get; set; } = new();
        public Dictionary<string, Asn1Type> TypeAliases { get; set; } = new();
    }

    public enum TagDefault
    {
        Explicit,
        Implicit,
        Automatic
    }

    public class Asn1Import
    {
        public string Module { get; set; }
        public List<string> Symbols { get; set; } = new();
    }

    public class Asn1TypeAssignment
    {
        public string Name { get; set; }
        public Asn1Type Type { get; set; }
        public string Comment { get; set; }
    }

    public abstract class Asn1Type
    {
    }

    public class Asn1SequenceType : Asn1Type
    {
        public List<Asn1Field> Fields { get; set; } = new();
        public bool Extensible { get; set; }
    }

    public class Asn1ChoiceType : Asn1Type
    {
        public List<Asn1Field> Fields { get; set; } = new();
        public bool Extensible { get; set; }
    }

    public class Asn1SequenceOfType : Asn1Type
    {
        public Asn1Type ElementType { get; set; }
    }

    public class Asn1SetOfType : Asn1Type
    {
        public Asn1Type ElementType { get; set; }
    }

    public class Asn1TaggedType : Asn1Type
    {
        public TagClass TagClass { get; set; } = TagClass.ContextSpecific;
        public int TagNumber { get; set; }
        public TaggingMode Mode { get; set; } = TaggingMode.Default;
        public Asn1Type InnerType { get; set; }
    }

    public enum TagClass
    {
        Universal,
        Application,
        ContextSpecific,
        Private
    }

    public enum TaggingMode
    {
        Default,
        Explicit,
        Implicit
    }

    public class Asn1Field
    {
        public string Name { get; set; }
        public Asn1Type Type { get; set; }
        public bool Optional { get; set; }
        public string DefaultValue { get; set; }
    }

    // Builtin types
    public class Asn1BooleanType : Asn1Type { }

    public class Asn1IntegerType : Asn1Type
    {
        public List<Asn1NamedNumber> NamedNumbers { get; set; }
    }

    public class Asn1NamedNumber
    {
        public string Name { get; set; }
        public long Value { get; set; }
    }

    public class Asn1BitStringType : Asn1Type
    {
        public List<Asn1NamedNumber> NamedBits { get; set; }
    }

    public class Asn1OctetStringType : Asn1Type { }
    public class Asn1NullType : Asn1Type { }

    public class Asn1ObjectIdentifierType : Asn1Type { }

    public class Asn1EnumeratedType : Asn1Type
    {
        public List<Asn1NamedNumber> Values { get; set; } = new();
        public bool Extensible { get; set; }
    }

    public class Asn1StringType : Asn1Type
    {
        public Asn1StringKind Kind { get; set; }
    }

    public enum Asn1StringKind
    {
        UTF8String,
        PrintableString,
        IA5String,
        VisibleString,
        GeneralString,
        BMPString,
        T61String
    }

    public class Asn1GeneralizedTimeType : Asn1Type { }
    public class Asn1UtcTimeType : Asn1Type { }

    public class Asn1ReferencedType : Asn1Type
    {
        public string ReferenceName { get; set; }
    }

    public class Asn1AnyType : Asn1Type { }
}
