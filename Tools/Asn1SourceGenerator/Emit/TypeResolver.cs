// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Asn1SourceGenerator.Model;

namespace Kerberos.NET.Asn1SourceGenerator.Emit
{
    public class ResolvedType
    {
        public string ClassName { get; set; } = "";
        public string Namespace { get; set; } = "";
        public AsnTypeAssignment Assignment { get; set; } = null!;
        public ResolvedTypeKind Kind { get; set; }
        public int? ApplicationTag { get; set; }
        public string? BaseClassName { get; set; }
        public List<ResolvedField> Fields { get; set; } = new List<ResolvedField>();
        public bool IsChoice { get; set; }
        public bool IsExtensible { get; set; }
        public AsnTagDefault ModuleTagDefault { get; set; }
    }

    public enum ResolvedTypeKind
    {
        Sequence,
        Choice,
        InheritedSequence,
        CollectionWrapper,
    }

    public class ResolvedField
    {
        public string AsnName { get; set; } = "";
        public string PropertyName { get; set; } = "";
        public string? ObsoleteAliasName { get; set; }
        public string CSharpType { get; set; } = "";
        public bool IsOptional { get; set; }
        public bool IsCollection { get; set; }
        public string? CollectionElementType { get; set; }
        public FieldEncodingInfo Encoding { get; set; } = new FieldEncodingInfo();
    }

    public class FieldEncodingInfo
    {
        public int? TagNumber { get; set; }
        public bool IsImplicit { get; set; }
        public FieldKind Kind { get; set; }
        public string? EnumType { get; set; }
        public bool IsFlagsEnum { get; set; }
        public string? ReferencedTypeName { get; set; }
    }

    public enum FieldKind
    {
        Integer,
        IntegerEnum,
        BitString,
        BitStringFlagsEnum,
        OctetString,
        GeneralString,
        UTF8String,
        IA5String,
        PrintableString,
        VisibleString,
        T61String,
        BMPString,
        GeneralizedTime,
        UtcTime,
        ObjectIdentifier,
        Boolean,
        CustomType,
        SequenceOf,
        SetOf,
        Enumerated,
        Any,
        BigInteger,
    }

    public static class TypeResolver
    {
        public static List<ResolvedType> Resolve(AsnSchema schema)
        {
            var results = new List<ResolvedType>();

            // Build a lookup of all type assignments across all modules for alias resolution
            var allAssignments = new Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)>();

            foreach (var module in schema.Modules)
            {
                foreach (var assignment in module.TypeAssignments)
                {
                    allAssignments[assignment.Name] = (module, assignment);
                }
            }

            foreach (var module in schema.Modules)
            {
                foreach (var assignment in module.TypeAssignments)
                {
                    var resolved = ResolveAssignment(module, assignment, allAssignments);

                    if (resolved != null)
                    {
                        results.Add(resolved);
                    }
                }
            }

            return results;
        }

        private static ResolvedType? ResolveAssignment(
            AsnModule module,
            AsnTypeAssignment assignment,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments)
        {
            var type = assignment.Type;

            // Skip pure type aliases (Realm ::= KerberosString, KerberosTime ::= GeneralizedTime, etc.)
            if (type is AsnTypeAlias)
            {
                return null;
            }

            // Skip primitive aliases (KerberosFlags ::= BIT STRING)
            if (type is AsnPrimitiveType && !(type is AsnSequenceType) && !(type is AsnChoiceType))
            {
                return null;
            }

            string className = ResolveClassName(module, assignment);
            string ns = assignment.Annotations.Namespace ?? module.Annotations.Namespace ?? "Kerberos.NET.Entities";

            if (type is AsnTaggedTypeAlias taggedAlias)
            {
                // AS-REQ ::= [APPLICATION 10] KDC-REQ → InheritedSequence
                int? appTag = taggedAlias.Tag?.Class == AsnTagClass.Application ? taggedAlias.Tag.Number : (int?)null;
                string baseClassName = ResolveReferencedClassName(taggedAlias.ReferencedName, module, allAssignments);

                return new ResolvedType
                {
                    ClassName = className,
                    Namespace = ns,
                    Assignment = assignment,
                    Kind = ResolvedTypeKind.InheritedSequence,
                    ApplicationTag = appTag,
                    BaseClassName = baseClassName,
                    ModuleTagDefault = module.TagDefault,
                };
            }

            if (type is AsnCollectionType collection)
            {
                // Skip collection types without explicit @cs-class — they're transparent aliases
                // (references to them will be resolved to elementType[] by the alias chain)
                if (string.IsNullOrEmpty(assignment.Annotations.ClassName))
                {
                    return null;
                }

                // METHOD-DATA ::= SEQUENCE OF PA-DATA → CollectionWrapper
                var elementField = ResolveCollectionWrapperField(module, assignment, collection, allAssignments);

                return new ResolvedType
                {
                    ClassName = className,
                    Namespace = ns,
                    Assignment = assignment,
                    Kind = ResolvedTypeKind.CollectionWrapper,
                    Fields = new List<ResolvedField> { elementField },
                    ModuleTagDefault = module.TagDefault,
                };
            }

            if (type is AsnSequenceType sequence)
            {
                int? appTag = sequence.Tag?.Class == AsnTagClass.Application ? sequence.Tag.Number : (int?)null;
                var fields = new List<ResolvedField>();

                foreach (var field in sequence.Fields)
                {
                    fields.Add(ResolveField(module, field, allAssignments));
                }

                return new ResolvedType
                {
                    ClassName = className,
                    Namespace = ns,
                    Assignment = assignment,
                    Kind = ResolvedTypeKind.Sequence,
                    ApplicationTag = appTag,
                    Fields = fields,
                    IsExtensible = sequence.Extensible,
                    ModuleTagDefault = module.TagDefault,
                };
            }

            if (type is AsnChoiceType choice)
            {
                var fields = new List<ResolvedField>();

                foreach (var alt in choice.Alternatives)
                {
                    var field = ResolveField(module, alt, allAssignments);

                    // CHOICE alternatives need value types nullable since only one is set at a time
                    if (!field.CSharpType.EndsWith("?") && !field.CSharpType.EndsWith("[]") && IsValueType(field.CSharpType))
                    {
                        field.CSharpType = field.CSharpType + "?";
                    }

                    fields.Add(field);
                }

                return new ResolvedType
                {
                    ClassName = className,
                    Namespace = ns,
                    Assignment = assignment,
                    Kind = ResolvedTypeKind.Choice,
                    IsChoice = true,
                    Fields = fields,
                    IsExtensible = choice.Extensible,
                    ModuleTagDefault = module.TagDefault,
                };
            }

            // Referenced types that are not aliases but have tags (e.g., [APPLICATION N] SomeType)
            if (type is AsnReferencedType referenced && type.Tag != null && type.Tag.Class == AsnTagClass.Application)
            {
                string baseClassName = ResolveReferencedClassName(referenced.ReferencedName, module, allAssignments);

                return new ResolvedType
                {
                    ClassName = className,
                    Namespace = ns,
                    Assignment = assignment,
                    Kind = ResolvedTypeKind.InheritedSequence,
                    ApplicationTag = type.Tag.Number,
                    BaseClassName = baseClassName,
                    ModuleTagDefault = module.TagDefault,
                };
            }

            return null;
        }

        private static string ResolveClassName(AsnModule module, AsnTypeAssignment assignment)
        {
            // @cs-class annotation overrides everything
            if (!string.IsNullOrEmpty(assignment.Annotations.ClassName))
            {
                return assignment.Annotations.ClassName!;
            }

            string prefix = module.Annotations.ClassPrefix ?? "";
            string baseName = ToPascalCase(assignment.Name);

            return prefix + baseName;
        }

        private static string ResolveReferencedClassName(
            string referencedName,
            AsnModule currentModule,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments)
        {
            if (allAssignments.TryGetValue(referencedName, out var entry))
            {
                return ResolveClassName(entry.Module, entry.Assignment);
            }

            // Fallback: apply current module prefix
            string prefix = currentModule.Annotations.ClassPrefix ?? "";
            return prefix + ToPascalCase(referencedName);
        }

        private static ResolvedField ResolveCollectionWrapperField(
            AsnModule module,
            AsnTypeAssignment assignment,
            AsnCollectionType collection,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments)
        {
            string className = !string.IsNullOrEmpty(assignment.Annotations.ClassName)
                ? assignment.Annotations.ClassName!
                : (module.Annotations.ClassPrefix ?? "") + ToPascalCase(assignment.Name);

            // Use @cs-name from type annotation if provided, otherwise auto-generate
            string propertyName;
            if (!string.IsNullOrEmpty(assignment.Annotations.PropertyName))
            {
                propertyName = assignment.Annotations.PropertyName!;
            }
            else
            {
                propertyName = ToPascalCase(assignment.Name);

                // If property name matches class name, use element type name instead
                if (propertyName == className)
                {
                    if (collection.ElementType is AsnReferencedType refElem)
                    {
                        propertyName = ToPascalCase(refElem.ReferencedName);
                    }
                    else
                    {
                        propertyName = propertyName + "Values";
                    }
                }
            }

            string elementType;
            FieldKind elementKind;
            string? referencedTypeName = null;
            string? enumType = null;

            ResolveElementType(module, collection.ElementType, allAssignments, out elementType, out elementKind, out referencedTypeName);

            // Use @cs-enum from type annotation to override element type
            if (!string.IsNullOrEmpty(assignment.Annotations.EnumType))
            {
                enumType = assignment.Annotations.EnumType!;
                elementType = enumType;
            }

            return new ResolvedField
            {
                AsnName = assignment.Name,
                PropertyName = propertyName,
                CSharpType = elementType + "[]",
                IsCollection = true,
                CollectionElementType = elementType,
                Encoding = new FieldEncodingInfo
                {
                    Kind = collection.IsSetOf ? FieldKind.SetOf : FieldKind.SequenceOf,
                    ReferencedTypeName = referencedTypeName,
                    EnumType = enumType,
                },
            };
        }

        private static void ResolveElementType(
            AsnModule module,
            AsnType elementType,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments,
            out string csharpType,
            out FieldKind kind,
            out string? referencedTypeName)
        {
            referencedTypeName = null;

            if (elementType is AsnPrimitiveType prim)
            {
                kind = MapPrimitiveKind(prim.Kind);
                csharpType = MapPrimitiveToCSharp(prim.Kind, null);
                return;
            }

            if (elementType is AsnReferencedType refType)
            {
                // Follow alias chains to determine the final type
                var resolved = ResolveAliasChain(refType.ReferencedName, allAssignments);

                if (resolved.IsPrimitive)
                {
                    kind = resolved.Kind;
                    csharpType = resolved.CSharpType;
                    return;
                }

                // It's a custom type reference
                kind = FieldKind.CustomType;
                referencedTypeName = ResolveReferencedClassName(refType.ReferencedName, module, allAssignments);
                csharpType = referencedTypeName;
                return;
            }

            // Fallback
            kind = FieldKind.Any;
            csharpType = "ReadOnlyMemory<byte>";
        }

        private static ResolvedField ResolveField(
            AsnModule module,
            AsnField field,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments)
        {
            string propertyName = field.Annotations.PropertyName ?? ToPascalCase(field.Name);

            // Determine obsolete alias: if annotation overrides the name, PascalCase of ASN name becomes alias
            string? obsoleteAlias = null;
            string naturalName = ToPascalCase(field.Name);

            if (!string.IsNullOrEmpty(field.Annotations.PropertyName) && field.Annotations.PropertyName != naturalName)
            {
                obsoleteAlias = naturalName;
            }

            // Resolve C# type and encoding info
            var fieldType = field.Type;
            int? tagNumber = null;
            bool isImplicit = false;

            // Extract tag info from the field's type
            if (fieldType.Tag != null)
            {
                tagNumber = fieldType.Tag.Number;

                if (fieldType.Tag.Mode.HasValue)
                {
                    isImplicit = fieldType.Tag.Mode.Value == AsnTagMode.Implicit;
                }
                else
                {
                    // Use module default
                    isImplicit = module.TagDefault == AsnTagDefault.Implicit;
                }
            }

            string csharpType;
            FieldKind fieldKind;
            string? enumType = null;
            bool isFlagsEnum = false;
            string? referencedTypeName = null;
            bool isCollection = false;
            string? collectionElementType = null;

            ResolveFieldType(
                module, field, fieldType, allAssignments,
                out csharpType, out fieldKind, out enumType, out isFlagsEnum,
                out referencedTypeName, out isCollection, out collectionElementType);

            // Make nullable if optional and appropriate type
            if (field.Optional)
            {
                if (csharpType == "ReadOnlyMemory<byte>")
                {
                    csharpType = "ReadOnlyMemory<byte>?";
                }
                else if (csharpType == "DateTimeOffset")
                {
                    csharpType = "DateTimeOffset?";
                }
                else if (csharpType == "int" || csharpType == "byte" || csharpType == "long" || csharpType == "bool")
                {
                    csharpType = csharpType + "?";
                }
                else if (fieldKind == FieldKind.IntegerEnum || fieldKind == FieldKind.Enumerated
                    || fieldKind == FieldKind.BitStringFlagsEnum)
                {
                    csharpType = csharpType + "?";
                }
            }

            return new ResolvedField
            {
                AsnName = field.Name,
                PropertyName = propertyName,
                ObsoleteAliasName = obsoleteAlias,
                CSharpType = csharpType,
                IsOptional = field.Optional,
                IsCollection = isCollection,
                CollectionElementType = collectionElementType,
                Encoding = new FieldEncodingInfo
                {
                    TagNumber = tagNumber,
                    IsImplicit = isImplicit,
                    Kind = fieldKind,
                    EnumType = enumType,
                    IsFlagsEnum = isFlagsEnum,
                    ReferencedTypeName = referencedTypeName,
                },
            };
        }

        private static void ResolveFieldType(
            AsnModule module,
            AsnField field,
            AsnType fieldType,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments,
            out string csharpType,
            out FieldKind fieldKind,
            out string? enumType,
            out bool isFlagsEnum,
            out string? referencedTypeName,
            out bool isCollection,
            out string? collectionElementType)
        {
            enumType = null;
            isFlagsEnum = false;
            referencedTypeName = null;
            isCollection = false;
            collectionElementType = null;

            if (fieldType is AsnPrimitiveType prim)
            {
                // Check annotations for enum mapping
                if (prim.Kind == AsnPrimitiveKind.Integer && !string.IsNullOrEmpty(field.Annotations.EnumType))
                {
                    enumType = field.Annotations.EnumType!;
                    fieldKind = FieldKind.IntegerEnum;
                    csharpType = enumType;
                    return;
                }

                if (prim.Kind == AsnPrimitiveKind.Enumerated && !string.IsNullOrEmpty(field.Annotations.EnumType))
                {
                    enumType = field.Annotations.EnumType!;
                    fieldKind = FieldKind.Enumerated;
                    csharpType = enumType;
                    return;
                }

                if (prim.Kind == AsnPrimitiveKind.BitString && !string.IsNullOrEmpty(field.Annotations.FlagsEnumType))
                {
                    enumType = field.Annotations.FlagsEnumType!;
                    isFlagsEnum = true;
                    fieldKind = FieldKind.BitStringFlagsEnum;
                    csharpType = enumType;
                    return;
                }

                if (prim.Kind == AsnPrimitiveKind.Integer && !string.IsNullOrEmpty(field.Annotations.BackingType))
                {
                    if (field.Annotations.BackingType == "bigint")
                    {
                        fieldKind = FieldKind.BigInteger;
                        csharpType = "System.Numerics.BigInteger";
                    }
                    else
                    {
                        fieldKind = FieldKind.Integer;
                        csharpType = field.Annotations.BackingType!;
                    }
                    return;
                }

                fieldKind = MapPrimitiveKind(prim.Kind);
                csharpType = MapPrimitiveToCSharp(prim.Kind, field.Annotations.BackingType);
                return;
            }

            if (fieldType is AsnCollectionType collection)
            {
                isCollection = true;

                string elementCSharpType;
                FieldKind elementKind;
                string? elementRefName;

                ResolveElementType(module, collection.ElementType, allAssignments,
                    out elementCSharpType, out elementKind, out elementRefName);

                // Check if field has @cs-enum to override the element type
                if ((elementKind == FieldKind.Integer) && !string.IsNullOrEmpty(field.Annotations.EnumType))
                {
                    enumType = field.Annotations.EnumType!;
                    elementCSharpType = enumType;
                    elementKind = FieldKind.IntegerEnum;
                }

                collectionElementType = elementCSharpType;
                csharpType = elementCSharpType + "[]";
                fieldKind = collection.IsSetOf ? FieldKind.SetOf : FieldKind.SequenceOf;
                referencedTypeName = elementRefName;
                return;
            }

            if (fieldType is AsnReferencedType refType)
            {
                // Follow alias chains
                var resolved = ResolveAliasChain(refType.ReferencedName, allAssignments);

                if (resolved.IsPrimitive)
                {
                    fieldKind = resolved.Kind;
                    csharpType = resolved.CSharpType;

                    // Check if the field has annotations that override the primitive mapping
                    if (resolved.Kind == FieldKind.Integer && !string.IsNullOrEmpty(field.Annotations.EnumType))
                    {
                        enumType = field.Annotations.EnumType!;
                        fieldKind = FieldKind.IntegerEnum;
                        csharpType = enumType;
                    }
                    else if (resolved.Kind == FieldKind.BitString && !string.IsNullOrEmpty(field.Annotations.FlagsEnumType))
                    {
                        enumType = field.Annotations.FlagsEnumType!;
                        isFlagsEnum = true;
                        fieldKind = FieldKind.BitStringFlagsEnum;
                        csharpType = enumType;
                    }

                    // Check for collection alias (e.g., HostAddresses → SEQUENCE OF HostAddress)
                    if (resolved.IsCollection)
                    {
                        // Check if the referenced type has a wrapper class with @cs-name
                        if (allAssignments.TryGetValue(refType.ReferencedName, out var collEntry2)
                            && !string.IsNullOrEmpty(collEntry2.Assignment.Annotations.ClassName)
                            && !string.IsNullOrEmpty(collEntry2.Assignment.Annotations.PropertyName))
                        {
                            fieldKind = FieldKind.CustomType;
                            csharpType = collEntry2.Assignment.Annotations.ClassName!;
                            referencedTypeName = csharpType;
                        }
                        else
                        {
                            isCollection = true;
                            collectionElementType = resolved.CollectionElementType;
                            csharpType = resolved.CollectionElementType + "[]";
                            fieldKind = FieldKind.SequenceOf;
                            referencedTypeName = resolved.CollectionReferencedTypeName;
                        }
                    }

                    return;
                }

                if (resolved.IsCollection)
                {
                    // Check if the referenced type is a collection wrapper with both @cs-class and @cs-name.
                    // When @cs-name is present, the wrapper is a meaningful type (e.g., KrbMethodData)
                    // and the field should use the wrapper class instead of inlining the array.
                    if (allAssignments.TryGetValue(refType.ReferencedName, out var collEntry)
                        && !string.IsNullOrEmpty(collEntry.Assignment.Annotations.ClassName)
                        && !string.IsNullOrEmpty(collEntry.Assignment.Annotations.PropertyName))
                    {
                        fieldKind = FieldKind.CustomType;
                        csharpType = collEntry.Assignment.Annotations.ClassName!;
                        referencedTypeName = csharpType;
                        return;
                    }

                    isCollection = true;
                    collectionElementType = resolved.CollectionElementType;
                    csharpType = resolved.CollectionElementType + "[]";
                    fieldKind = FieldKind.SequenceOf;
                    referencedTypeName = resolved.CollectionReferencedTypeName;
                    return;
                }

                // Custom type reference
                fieldKind = FieldKind.CustomType;
                referencedTypeName = ResolveReferencedClassName(refType.ReferencedName, module, allAssignments);
                csharpType = referencedTypeName;
                return;
            }

            if (fieldType is AsnAnyType)
            {
                fieldKind = FieldKind.Any;
                csharpType = "ReadOnlyMemory<byte>";
                return;
            }

            // Fallback
            fieldKind = FieldKind.Any;
            csharpType = "ReadOnlyMemory<byte>";
        }

        private struct AliasResolution
        {
            public bool IsPrimitive;
            public FieldKind Kind;
            public string CSharpType;
            public bool IsCollection;
            public string? CollectionElementType;
            public string? CollectionReferencedTypeName;
        }

        private static AliasResolution ResolveAliasChain(
            string typeName,
            Dictionary<string, (AsnModule Module, AsnTypeAssignment Assignment)> allAssignments)
        {
            var visited = new HashSet<string>();
            string current = typeName;

            while (visited.Add(current))
            {
                if (!allAssignments.TryGetValue(current, out var entry))
                {
                    break;
                }

                var type = entry.Assignment.Type;

                if (type is AsnPrimitiveType prim)
                {
                    return new AliasResolution
                    {
                        IsPrimitive = true,
                        Kind = MapPrimitiveKind(prim.Kind),
                        CSharpType = MapPrimitiveToCSharp(prim.Kind, null),
                    };
                }

                if (type is AsnCollectionType collection)
                {
                    // If the collection type has @cs-class, it's a wrapper class, not a transparent collection
                    if (!string.IsNullOrEmpty(entry.Assignment.Annotations.ClassName))
                    {
                        // Treat as a custom type, not a collection
                        break;
                    }

                    string elementType;
                    FieldKind elementKind;
                    string? elementRefName;

                    ResolveElementType(entry.Module, collection.ElementType, allAssignments,
                        out elementType, out elementKind, out elementRefName);

                    return new AliasResolution
                    {
                        IsCollection = true,
                        CollectionElementType = elementType,
                        CollectionReferencedTypeName = elementRefName,
                        Kind = FieldKind.SequenceOf,
                        CSharpType = elementType + "[]",
                    };
                }

                if (type is AsnTypeAlias alias)
                {
                    current = alias.ReferencedName;
                    continue;
                }

                if (type is AsnReferencedType refType)
                {
                    current = refType.ReferencedName;
                    continue;
                }

                // Sequence or Choice type — not a primitive alias
                break;
            }

            return new AliasResolution { IsPrimitive = false };
        }

        private static FieldKind MapPrimitiveKind(AsnPrimitiveKind kind)
        {
            switch (kind)
            {
                case AsnPrimitiveKind.Boolean: return FieldKind.Boolean;
                case AsnPrimitiveKind.Integer: return FieldKind.Integer;
                case AsnPrimitiveKind.BitString: return FieldKind.BitString;
                case AsnPrimitiveKind.OctetString: return FieldKind.OctetString;
                case AsnPrimitiveKind.ObjectIdentifier: return FieldKind.ObjectIdentifier;
                case AsnPrimitiveKind.Enumerated: return FieldKind.Enumerated;
                case AsnPrimitiveKind.UTF8String: return FieldKind.UTF8String;
                case AsnPrimitiveKind.PrintableString: return FieldKind.PrintableString;
                case AsnPrimitiveKind.IA5String: return FieldKind.IA5String;
                case AsnPrimitiveKind.GeneralString: return FieldKind.GeneralString;
                case AsnPrimitiveKind.VisibleString: return FieldKind.VisibleString;
                case AsnPrimitiveKind.T61String: return FieldKind.T61String;
                case AsnPrimitiveKind.BMPString: return FieldKind.BMPString;
                case AsnPrimitiveKind.GeneralizedTime: return FieldKind.GeneralizedTime;
                case AsnPrimitiveKind.UtcTime: return FieldKind.UtcTime;
                case AsnPrimitiveKind.Any: return FieldKind.Any;
                default: return FieldKind.Any;
            }
        }

        private static string MapPrimitiveToCSharp(AsnPrimitiveKind kind, string? backingType)
        {
            switch (kind)
            {
                case AsnPrimitiveKind.Boolean:
                    return "bool";
                case AsnPrimitiveKind.Integer:
                    return backingType ?? "int";
                case AsnPrimitiveKind.BitString:
                    return "ReadOnlyMemory<byte>";
                case AsnPrimitiveKind.OctetString:
                    return "ReadOnlyMemory<byte>";
                case AsnPrimitiveKind.ObjectIdentifier:
                    return "Oid";
                case AsnPrimitiveKind.Enumerated:
                    return "int";
                case AsnPrimitiveKind.UTF8String:
                case AsnPrimitiveKind.PrintableString:
                case AsnPrimitiveKind.IA5String:
                case AsnPrimitiveKind.GeneralString:
                case AsnPrimitiveKind.VisibleString:
                case AsnPrimitiveKind.T61String:
                case AsnPrimitiveKind.BMPString:
                    return "string";
                case AsnPrimitiveKind.GeneralizedTime:
                case AsnPrimitiveKind.UtcTime:
                    return "DateTimeOffset";
                case AsnPrimitiveKind.Any:
                    return "ReadOnlyMemory<byte>";
                case AsnPrimitiveKind.Null:
                    return "ReadOnlyMemory<byte>";
                default:
                    return "ReadOnlyMemory<byte>";
            }
        }

        public static string ToPascalCase(string asnName)
        {
            if (string.IsNullOrEmpty(asnName))
            {
                return asnName;
            }

            var segments = asnName.Split('-');
            var result = new List<string>();

            foreach (var segment in segments)
            {
                if (segment.Length == 0)
                {
                    continue;
                }

                if (segment.Length == 1)
                {
                    result.Add(segment.ToUpperInvariant());
                }
                else if (IsAllUpperCase(segment))
                {
                    // ALL CAPS segment like "KDC" or "REQ" → title case "Kdc", "Req"
                    result.Add(char.ToUpperInvariant(segment[0]) + segment.Substring(1).ToLowerInvariant());
                }
                else
                {
                    // Mixed case segment like "Enc" or "MechTypeList" → preserve, ensure first char upper
                    result.Add(char.ToUpperInvariant(segment[0]) + segment.Substring(1));
                }
            }

            return string.Join("", result);
        }

        private static bool IsAllUpperCase(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsLetter(s[i]) && !char.IsUpper(s[i]))
                    return false;
            }
            return true;
        }

        private static bool IsValueType(string csharpType)
        {
            // Known reference types in ASN.1 mapping
            switch (csharpType)
            {
                case "string":
                case "Oid":
                    return false;
                default:
                    // Primitive value types
                    if (csharpType == "int" || csharpType == "long" || csharpType == "byte"
                        || csharpType == "bool" || csharpType == "DateTimeOffset"
                        || csharpType == "ReadOnlyMemory<byte>"
                        || csharpType == "System.Numerics.BigInteger")
                    {
                        return true;
                    }

                    // Custom types (classes) are reference types
                    // Enum types are value types - they won't match the above but
                    // they also won't be typical CustomType class names. 
                    // However, in CHOICE alternatives the field kind tells us more.
                    // For safety, don't make unknown types nullable - they're likely classes.
                    return false;
            }
        }
    }
}
