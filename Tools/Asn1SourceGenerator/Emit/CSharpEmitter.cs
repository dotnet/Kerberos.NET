// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET.Asn1SourceGenerator.Model;

namespace Kerberos.NET.Asn1SourceGenerator.Emit
{
    public static class CSharpEmitter
    {
        public static string Emit(ResolvedType type)
        {
            switch (type.Kind)
            {
                case ResolvedTypeKind.Sequence:
                    return EmitSequence(type);
                case ResolvedTypeKind.Choice:
                    return EmitChoice(type);
                case ResolvedTypeKind.InheritedSequence:
                    return EmitInheritedSequence(type);
                case ResolvedTypeKind.CollectionWrapper:
                    return EmitCollectionWrapper(type);
                default:
                    throw new NotSupportedException($"Unsupported type kind: {type.Kind}");
            }
        }

        // ─── Sequence (with or without APPLICATION tag) ──────────────────

        private static string EmitSequence(ResolvedType type)
        {
            var w = new IndentedWriter();
            bool hasApp = type.ApplicationTag.HasValue;
            bool hasCollections = type.Fields.Any(f => f.IsCollection);

            WriteHeader(w);
            WriteUsings(w, hasCollections: hasCollections, isChoice: false);
            w.WriteLine();
            w.WriteLine($"namespace {type.Namespace}");
            w.OpenBrace();
            w.WriteLine($"public partial class {type.ClassName}");
            w.OpenBrace();

            WriteAsnComment(w, type);

            WriteProperties(w, type.Fields);
            WriteObsoleteAliases(w, type.Fields);

            w.WriteLine("// Encoding methods");

            if (hasApp)
            {
                EmitSequenceAppEncodeMethods(w, type);
            }
            else
            {
                EmitSequenceNonAppEncodeMethods(w, type);
            }

            EmitSequenceEncodeTagMethod(w, type);
            EmitEncodeApplicationWriter(w, type);

            if (hasApp)
            {
                EmitApplicationTagField(w, type.ApplicationTag!.Value);
                w.WriteLine();
                EmitEncodeApplicationVirtualOverride(w);
            }
            else
            {
                EmitEncodeApplicationVirtualEmpty(w);
            }

            w.WriteLine();
            EmitEncodeApplicationTagHelper(w);
            w.WriteLine();

            if (hasApp)
            {
                EmitApplicationDecodeStaticMethod(w, type);
                EmitApplicationDecodeGenericMethod(w, type);
            }
            else
            {
                EmitSequenceDecodePublic(w, type);
                EmitSequenceDecodeWithRuleSet(w, type);
            }

            w.WriteLine();
            EmitDecodeExpectedTag(w, type);
            w.WriteLine();
            EmitDecodeExpectedTagRuleSet(w, type);
            w.WriteLine();
            EmitDecodeGenericNoTag(w, type, hasApp);
            w.WriteLine();
            EmitDecodeGenericWithTag(w, type);

            w.CloseBrace(); // class
            w.CloseBrace(); // namespace

            return w.ToString();
        }

        // ─── Choice ─────────────────────────────────────────────────────

        private static string EmitChoice(ResolvedType type)
        {
            var w = new IndentedWriter();

            WriteHeader(w);
            WriteUsings(w, hasCollections: false, isChoice: true);
            w.WriteLine();
            w.WriteLine($"namespace {type.Namespace}");
            w.OpenBrace();
            w.WriteLine($"public partial class {type.ClassName}");
            w.OpenBrace();

            WriteAsnComment(w, type);

            WriteProperties(w, type.Fields);

            // DEBUG static constructor with tag uniqueness validation
            w.WriteLine("#if DEBUG");
            w.WriteLine($"static {type.ClassName}()");
            w.OpenBrace();
            w.WriteLine("var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();");
            w.WriteLine("Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>");
            w.OpenBrace();
            w.WriteLine("if (usedTags.TryGetValue(tag, out string existing))");
            w.OpenBrace();
            w.WriteLine("throw new InvalidOperationException($\"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'\");");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("usedTags.Add(tag, fieldName);");
            w.CloseBrace(";");
            w.WriteLine();

            foreach (var field in type.Fields)
            {
                if (field.Encoding.TagNumber.HasValue)
                {
                    w.WriteLine($"ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value}), \"{field.PropertyName}\");");
                }
            }

            w.CloseBrace();
            w.WriteLine("#endif");

            // Encode methods
            w.WriteLine("// Encoding methods");
            EmitChoiceEncodePublic(w);
            w.WriteLine();
            EmitChoiceEncodeInternal(w, type);
            w.WriteLine();
            EmitEncodeApplicationTagHelper(w, inlineEncode: true);
            w.WriteLine();

            // Decode methods
            EmitChoiceDecodePublic(w, type);
            w.WriteLine();
            EmitChoiceDecodeWithRuleSet(w, type);
            w.WriteLine();
            EmitChoiceDecodeGeneric(w, type);

            w.CloseBrace(); // class
            w.CloseBrace(); // namespace

            return w.ToString();
        }

        // ─── InheritedSequence ───────────────────────────────────────────

        private static string EmitInheritedSequence(ResolvedType type)
        {
            var w = new IndentedWriter();

            WriteHeader(w);
            w.WriteLine("using System;");
            w.WriteLine("using System.Security.Cryptography.Asn1;");
            w.WriteLine();
            w.WriteLine($"namespace {type.Namespace}");
            w.OpenBrace();
            w.WriteLine($"public partial class {type.ClassName} : {type.BaseClassName}");
            w.OpenBrace();

            WriteAsnComment(w, type);

            EmitApplicationTagField(w, type.ApplicationTag!.Value);
            w.WriteLine();
            // InheritedSequence overrides the base class virtual method
            w.WriteLine("public override ReadOnlyMemory<byte> EncodeApplication() ");
            w.OpenBrace();
            w.WriteLine("return EncodeApplication(ApplicationTag);");
            w.CloseBrace();
            w.WriteLine();

            // DecodeApplication
            w.WriteLine($"public static {type.ClassName} DecodeApplication(ReadOnlyMemory<byte> encoded)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
            w.WriteLine();
            w.WriteLine("var sequence = reader.ReadSequence(ApplicationTag);");
            w.WriteLine();
            w.WriteLine($"{type.ClassName} decoded;");
            w.WriteLine("Decode(sequence, out decoded);");
            w.WriteLine("sequence.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("return decoded;");
            w.CloseBrace();

            w.CloseBrace(); // class
            w.CloseBrace(); // namespace

            return w.ToString();
        }

        // ─── CollectionWrapper ───────────────────────────────────────────

        private static string EmitCollectionWrapper(ResolvedType type)
        {
            var w = new IndentedWriter();
            var field = type.Fields[0];

            WriteHeader(w);
            WriteUsings(w, hasCollections: true, isChoice: true);
            w.WriteLine();
            w.WriteLine($"namespace {type.Namespace}");
            w.OpenBrace();
            w.WriteLine($"public partial class {type.ClassName}");
            w.OpenBrace();

            WriteAsnComment(w, type);

            w.WriteLine($"public {field.CSharpType} {field.PropertyName} {{ get; set; }}");
            w.WriteLine();

            // DEBUG static constructor
            w.WriteLine("#if DEBUG");
            w.WriteLine($"static {type.ClassName}()");
            w.OpenBrace();
            w.WriteLine("var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();");
            w.WriteLine("Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>");
            w.OpenBrace();
            w.WriteLine("if (usedTags.TryGetValue(tag, out string existing))");
            w.OpenBrace();
            w.WriteLine("throw new InvalidOperationException($\"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'\");");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("usedTags.Add(tag, fieldName);");
            w.CloseBrace(";");
            w.WriteLine();
            w.WriteLine($"ensureUniqueTag(Asn1Tag.Sequence, \"{field.PropertyName}\");");
            w.CloseBrace();
            w.WriteLine("#endif");

            // Encode methods
            w.WriteLine("// Encoding methods");
            EmitChoiceEncodePublic(w);
            w.WriteLine();
            EmitCollectionWrapperEncode(w, type);
            w.WriteLine();
            EmitEncodeApplicationTagHelper(w, inlineEncode: true);
            w.WriteLine();

            // Decode methods
            EmitCollectionWrapperDecodePublic(w, type);
            w.WriteLine();
            EmitCollectionWrapperDecodeWithRuleSet(w, type);
            w.WriteLine();
            EmitCollectionWrapperDecodeGeneric(w, type);

            w.CloseBrace(); // class
            w.CloseBrace(); // namespace

            return w.ToString();
        }

        // ─── Encode helpers ─────────────────────────────────────────────

        private static void EmitSequenceAppEncodeMethods(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine("internal void Encode(AsnWriter writer)");
            w.OpenBrace();
            w.WriteLine("EncodeApplication(writer, ApplicationTag);");
            w.CloseBrace();
            w.WriteLine();
        }

        private static void EmitSequenceNonAppEncodeMethods(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine("public ReadOnlyMemory<byte> Encode()");
            w.OpenBrace();
            w.WriteLine("var writer = new AsnWriter(AsnEncodingRules.DER);");
            w.WriteLine();
            w.WriteLine("Encode(writer);");
            w.WriteLine();
            w.WriteLine("return writer.EncodeAsMemory();");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("internal void Encode(AsnWriter writer)");
            w.OpenBrace();
            w.WriteLine("Encode(writer, Asn1Tag.Sequence);");
            w.CloseBrace();
            w.WriteLine();
        }

        private static void EmitSequenceEncodeTagMethod(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine("internal void Encode(AsnWriter writer, Asn1Tag tag)");
            w.OpenBrace();
            w.WriteLine("writer.PushSequence(tag);");
            w.WriteLine();

            foreach (var field in type.Fields)
            {
                EmitFieldEncode(w, field);
            }

            w.WriteLine("writer.PopSequence(tag);");
            w.CloseBrace();
            w.WriteLine();
        }

        private static void EmitEncodeApplicationWriter(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine("internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)");
            w.OpenBrace();
            w.WriteLine("writer.PushSequence(tag);");
            w.WriteLine();
            w.WriteLine("this.Encode(writer, Asn1Tag.Sequence);");
            w.WriteLine();
            w.WriteLine("writer.PopSequence(tag);");
            w.CloseBrace();
        }

        private static void EmitApplicationTagField(IndentedWriter w, int tagNumber)
        {
            w.WriteLine($"private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, {tagNumber});");
        }

        private static void EmitEncodeApplicationVirtualOverride(IndentedWriter w)
        {
            w.WriteLine("public virtual ReadOnlyMemory<byte> EncodeApplication() ");
            w.OpenBrace();
            w.WriteLine("return EncodeApplication(ApplicationTag);");
            w.CloseBrace();
        }

        private static void EmitEncodeApplicationVirtualEmpty(IndentedWriter w)
        {
            w.WriteLine("public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();");
        }

        private static void EmitEncodeApplicationTagHelper(IndentedWriter w, bool inlineEncode = false)
        {
            w.WriteLine("internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)");
            w.OpenBrace();
            w.WriteLine("using (var writer = new AsnWriter(AsnEncodingRules.DER))");
            w.OpenBrace();
            if (inlineEncode)
            {
                w.WriteLine("writer.PushSequence(tag);");
                w.WriteLine();
                w.WriteLine("this.Encode(writer);");
                w.WriteLine();
                w.WriteLine("writer.PopSequence(tag);");
                w.WriteLine();
            }
            else
            {
                w.WriteLine("EncodeApplication(writer, tag);");
                w.WriteLine();
            }
            w.WriteLine("return writer.EncodeAsMemory();");
            w.CloseBrace();
            w.CloseBrace();
        }

        // ─── Decode helpers (Sequence) ──────────────────────────────────

        private static void EmitApplicationDecodeStaticMethod(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"public static {type.ClassName} DecodeApplication(ReadOnlyMemory<byte> encoded)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
            w.WriteLine();
            w.WriteLine("var sequence = reader.ReadSequence(ApplicationTag);");
            w.WriteLine();
            w.WriteLine($"{type.ClassName} decoded;");
            w.WriteLine("Decode(sequence, Asn1Tag.Sequence, out decoded);");
            w.WriteLine("sequence.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("return decoded;");
            w.CloseBrace();
            w.WriteLine();
        }

        private static void EmitApplicationDecodeGenericMethod(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} DecodeApplication<T>(AsnReader reader, out T decoded)");
            w.WriteLine($"  where T: {type.ClassName}, new()");
            w.OpenBrace();
            w.WriteLine("var sequence = reader.ReadSequence(ApplicationTag);");
            w.WriteLine();
            w.WriteLine("Decode(sequence, Asn1Tag.Sequence, out decoded);");
            w.WriteLine("sequence.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine();
            w.WriteLine("return decoded;");
            w.CloseBrace();
        }

        private static void EmitSequenceDecodePublic(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"public static {type.ClassName} Decode(ReadOnlyMemory<byte> data)");
            w.OpenBrace();
            w.WriteLine("return Decode(data, AsnEncodingRules.DER);");
            w.CloseBrace();
            w.WriteLine();
        }

        private static void EmitSequenceDecodeWithRuleSet(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            w.OpenBrace();
            w.WriteLine("return Decode(Asn1Tag.Sequence, encoded, ruleSet);");
            w.CloseBrace();
        }

        private static void EmitDecodeExpectedTag(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
            w.WriteLine();
            w.WriteLine($"Decode(reader, expectedTag, out {type.ClassName} decoded);");
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine("return decoded;");
            w.CloseBrace();
        }

        private static void EmitDecodeExpectedTagRuleSet(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, ruleSet);");
            w.WriteLine();
            w.WriteLine($"Decode(reader, expectedTag, out {type.ClassName} decoded);");
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine("return decoded;");
            w.CloseBrace();
        }

        private static void EmitDecodeGenericNoTag(IndentedWriter w, ResolvedType type, bool hasApp)
        {
            w.WriteLine($"internal static void Decode<T>(AsnReader reader, out T decoded)");
            w.WriteLine($"  where T: {type.ClassName}, new()");
            w.OpenBrace();
            w.WriteLine("if (reader == null)");
            w.OpenBrace();
            w.WriteLine("throw new ArgumentNullException(nameof(reader));");
            w.CloseBrace();
            w.WriteLine();

            if (hasApp)
            {
                w.WriteLine("DecodeApplication(reader, out decoded);");
            }
            else
            {
                w.WriteLine("Decode(reader, Asn1Tag.Sequence, out decoded);");
            }

            w.CloseBrace();
        }

        private static void EmitDecodeGenericWithTag(IndentedWriter w, ResolvedType type)
        {
            bool hasCollections = type.Fields.Any(f => f.IsCollection);

            w.WriteLine($"internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)");
            w.WriteLine($"  where T: {type.ClassName}, new()");
            w.OpenBrace();
            w.WriteLine("if (reader == null)");
            w.OpenBrace();
            w.WriteLine("throw new ArgumentNullException(nameof(reader));");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("decoded = new T();");
            w.WriteLine();
            w.WriteLine("AsnReader sequenceReader = reader.ReadSequence(expectedTag);");
            w.WriteLine("AsnReader explicitReader;");

            if (hasCollections)
            {
                w.WriteLine("AsnReader collectionReader;");
            }

            w.WriteLine();

            foreach (var field in type.Fields)
            {
                EmitFieldDecode(w, field, type);
            }

            w.WriteLine("sequenceReader.ThrowIfNotEmpty();");
            w.CloseBrace();
        }

        // ─── Choice encode/decode ───────────────────────────────────────

        private static void EmitChoiceEncodePublic(IndentedWriter w)
        {
            w.WriteLine("public ReadOnlyMemory<byte> Encode()");
            w.OpenBrace();
            w.WriteLine("var writer = new AsnWriter(AsnEncodingRules.DER);");
            w.WriteLine();
            w.WriteLine("Encode(writer);");
            w.WriteLine();
            w.WriteLine("return writer.EncodeAsMemory();");
            w.CloseBrace();
        }

        private static void EmitChoiceEncodeInternal(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine("internal void Encode(AsnWriter writer)");
            w.OpenBrace();
            w.WriteLine("bool wroteValue = false; ");
            w.WriteLine();

            foreach (var field in type.Fields)
            {
                w.WriteLine($"if (Asn1Extension.HasValue({field.PropertyName}))");
                w.OpenBrace();
                w.WriteLine("if (wroteValue)");
                w.OpenBrace();
                w.WriteLine("throw new CryptographicException();");
                w.CloseBrace();
                w.WriteLine();

                if (field.Encoding.TagNumber.HasValue)
                {
                    string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value})";
                    w.WriteLine($"writer.PushSequence({tag});");
                    EmitFieldValueEncode(w, field);
                    w.WriteLine($"writer.PopSequence({tag});");
                }
                else
                {
                    EmitFieldValueEncode(w, field);
                }

                w.WriteLine("wroteValue = true;");
                w.CloseBrace();
            }

            w.WriteLine("if (!wroteValue)");
            w.OpenBrace();
            w.WriteLine("throw new CryptographicException();");
            w.CloseBrace();
            w.CloseBrace();
        }

        private static void EmitChoiceDecodePublic(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"public static {type.ClassName} Decode(ReadOnlyMemory<byte> data)");
            w.OpenBrace();
            w.WriteLine("return Decode(data, AsnEncodingRules.DER);");
            w.CloseBrace();
        }

        private static void EmitChoiceDecodeWithRuleSet(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, ruleSet);");
            w.WriteLine();
            w.WriteLine($"Decode(reader, out {type.ClassName} decoded);");
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine("return decoded;");
            w.CloseBrace();
        }

        private static void EmitChoiceDecodeGeneric(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static void Decode<T>(AsnReader reader, out T decoded)");
            w.WriteLine($"  where T: {type.ClassName}, new()");
            w.OpenBrace();
            w.WriteLine("if (reader == null)");
            w.OpenBrace();
            w.WriteLine("throw new ArgumentNullException(nameof(reader));");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("decoded = new T();");
            w.WriteLine();
            w.WriteLine("Asn1Tag tag = reader.PeekTag();");
            w.WriteLine("AsnReader explicitReader;");
            w.WriteLine();

            bool first = true;

            foreach (var field in type.Fields)
            {
                string keyword = first ? "if" : "else if";
                first = false;

                if (field.Encoding.TagNumber.HasValue)
                {
                    string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value})";
                    w.WriteLine($"{keyword} (tag.HasSameClassAndValue({tag}))");
                    w.OpenBrace();
                    w.WriteLine($"explicitReader = reader.ReadSequence({tag});");
                    EmitChoiceFieldDecode(w, field);
                    w.WriteLine("explicitReader.ThrowIfNotEmpty();");
                    w.CloseBrace();
                }
            }

            w.WriteLine("else");
            w.OpenBrace();
            w.WriteLine("throw new CryptographicException();");
            w.CloseBrace();
            w.CloseBrace();
        }

        // ─── CollectionWrapper encode/decode ────────────────────────────

        private static void EmitCollectionWrapperEncode(IndentedWriter w, ResolvedType type)
        {
            var field = type.Fields[0];

            w.WriteLine("internal void Encode(AsnWriter writer)");
            w.OpenBrace();
            w.WriteLine("bool wroteValue = false; ");
            w.WriteLine();
            w.WriteLine($"if ({field.PropertyName} != null)");
            w.OpenBrace();
            w.WriteLine("if (wroteValue)");
            w.OpenBrace();
            w.WriteLine("throw new CryptographicException();");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("writer.PushSequence();");
            w.WriteLine();
            EmitCollectionEncodeLoop(w, field);
            w.WriteLine();
            w.WriteLine("writer.PopSequence();");
            w.WriteLine();
            w.WriteLine("wroteValue = true;");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("if (!wroteValue)");
            w.OpenBrace();
            w.WriteLine("throw new CryptographicException();");
            w.CloseBrace();
            w.CloseBrace();
        }

        private static void EmitCollectionWrapperDecodePublic(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"public static {type.ClassName} Decode(ReadOnlyMemory<byte> data)");
            w.OpenBrace();
            w.WriteLine("return Decode(data, AsnEncodingRules.DER);");
            w.CloseBrace();
        }

        private static void EmitCollectionWrapperDecodeWithRuleSet(IndentedWriter w, ResolvedType type)
        {
            w.WriteLine($"internal static {type.ClassName} Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            w.OpenBrace();
            w.WriteLine("AsnReader reader = new AsnReader(encoded, ruleSet);");
            w.WriteLine();
            w.WriteLine($"Decode(reader, out {type.ClassName} decoded);");
            w.WriteLine("reader.ThrowIfNotEmpty();");
            w.WriteLine("return decoded;");
            w.CloseBrace();
        }

        private static void EmitCollectionWrapperDecodeGeneric(IndentedWriter w, ResolvedType type)
        {
            var field = type.Fields[0];
            string elementType = field.CollectionElementType ?? "object";

            w.WriteLine($"internal static void Decode<T>(AsnReader reader, out T decoded)");
            w.WriteLine($"  where T: {type.ClassName}, new()");
            w.OpenBrace();
            w.WriteLine("if (reader == null)");
            w.OpenBrace();
            w.WriteLine("throw new ArgumentNullException(nameof(reader));");
            w.CloseBrace();
            w.WriteLine();
            w.WriteLine("decoded = new T();");
            w.WriteLine();
            w.WriteLine("Asn1Tag tag = reader.PeekTag();");
            w.WriteLine("AsnReader collectionReader;");
            w.WriteLine();
            w.WriteLine("if (tag.HasSameClassAndValue(Asn1Tag.Sequence))");
            w.OpenBrace();

            EmitCollectionDecode(w, field, "reader");

            w.CloseBrace();
            w.WriteLine("else");
            w.OpenBrace();
            w.WriteLine("throw new CryptographicException();");
            w.CloseBrace();
            w.CloseBrace();
        }

        // ─── Field encoding ─────────────────────────────────────────────

        private static void EmitFieldEncode(IndentedWriter w, ResolvedField field)
        {
            if (field.IsOptional)
            {
                w.WriteLine($"if (Asn1Extension.HasValue({field.PropertyName}))");
                w.OpenBrace();
            }

            if (field.Encoding.TagNumber.HasValue)
            {
                if (field.Encoding.IsImplicit)
                {
                    EmitImplicitFieldEncode(w, field);
                }
                else
                {
                    string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value})";
                    w.WriteLine($"writer.PushSequence({tag});");
                    EmitFieldValueEncode(w, field);
                    w.WriteLine($"writer.PopSequence({tag});");
                }
            }
            else
            {
                EmitFieldValueEncode(w, field);
            }

            if (field.IsOptional)
            {
                w.CloseBrace();
            }
        }

        private static void EmitImplicitFieldEncode(IndentedWriter w, ResolvedField field)
        {
            string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber!.Value})";

            switch (field.Encoding.Kind)
            {
                case FieldKind.OctetString:
                    string span = IsNullableValueType(field) ? $"{field.PropertyName}.Value.Span" : $"{field.PropertyName}.Span";
                    w.WriteLine($"writer.WriteOctetString({tag}, {span});");
                    break;
                case FieldKind.BitString:
                    w.WriteLine($"writer.WriteBitString({tag}, {field.PropertyName}.Span);");
                    break;
                default:
                    // Fallback: use explicit wrapping for implicit tags on other types
                    w.WriteLine($"writer.PushSequence({tag});");
                    EmitFieldValueEncode(w, field);
                    w.WriteLine($"writer.PopSequence({tag});");
                    break;
            }
        }

        private static bool IsNullableValueType(ResolvedField field) => field.CSharpType.EndsWith("?");

        private static void EmitFieldValueEncode(IndentedWriter w, ResolvedField field)
        {
            bool isNullable = IsNullableValueType(field);

            switch (field.Encoding.Kind)
            {
                case FieldKind.Integer:
                {
                    string val = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteInteger({val});");
                    break;
                }

                case FieldKind.IntegerEnum:
                {
                    string val = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteInteger((long){val});");
                    break;
                }

                case FieldKind.BitString:
                    string bitSpan = isNullable ? $"{field.PropertyName}.Value.Span" : $"{field.PropertyName}.Span";
                    w.WriteLine($"writer.WriteBitString({bitSpan});");
                    break;

                case FieldKind.BitStringFlagsEnum:
                {
                    string val = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteBitString({val}.AsReadOnlySpan());");
                    break;
                }

                case FieldKind.OctetString:
                    string octetSpan = isNullable ? $"{field.PropertyName}.Value.Span" : $"{field.PropertyName}.Span";
                    w.WriteLine($"writer.WriteOctetString({octetSpan});");
                    break;

                case FieldKind.GeneralString:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.GeneralString, {field.PropertyName});");
                    break;

                case FieldKind.UTF8String:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.UTF8String, {field.PropertyName});");
                    break;

                case FieldKind.IA5String:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.IA5String, {field.PropertyName});");
                    break;

                case FieldKind.PrintableString:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.PrintableString, {field.PropertyName});");
                    break;

                case FieldKind.VisibleString:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.VisibleString, {field.PropertyName});");
                    break;

                case FieldKind.T61String:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.T61String, {field.PropertyName});");
                    break;

                case FieldKind.BMPString:
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.BMPString, {field.PropertyName});");
                    break;

                case FieldKind.GeneralizedTime:
                    string timeVal = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteGeneralizedTime({timeVal});");
                    break;

                case FieldKind.UtcTime:
                    string utcVal = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteUtcTime({utcVal});");
                    break;

                case FieldKind.ObjectIdentifier:
                    w.WriteLine($"writer.WriteObjectIdentifier({field.PropertyName});");
                    break;

                case FieldKind.Boolean:
                {
                    string val = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteBoolean({val});");
                    break;
                }

                case FieldKind.CustomType:
                    w.WriteLine($"{field.PropertyName}?.Encode(writer);");
                    break;

                case FieldKind.SequenceOf:
                case FieldKind.SetOf:
                    w.WriteLine("writer.PushSequence();");
                    w.WriteLine();
                    EmitCollectionEncodeLoop(w, field);
                    w.WriteLine();
                    w.WriteLine("writer.PopSequence();");
                    w.WriteLine();
                    break;

                case FieldKind.Enumerated:
                {
                    string val = isNullable ? $"{field.PropertyName}.Value" : field.PropertyName;
                    w.WriteLine($"writer.WriteInteger((long){val});");
                    break;
                }

                case FieldKind.Any:
                    string anySpan = field.IsOptional ? $"{field.PropertyName}.Value.Span" : $"{field.PropertyName}.Span";
                    w.WriteLine($"writer.WriteEncodedValue({anySpan});");
                    break;

                case FieldKind.BigInteger:
                    w.WriteLine($"writer.WriteInteger({field.PropertyName});");
                    break;
            }
        }

        private static void EmitCollectionEncodeLoop(IndentedWriter w, ResolvedField field)
        {
            string elementType = field.CollectionElementType ?? "object";

            w.WriteLine($"for (int i = 0; i < {field.PropertyName}.Length; i++)");
            w.OpenBrace();

            if (field.Encoding.ReferencedTypeName != null)
            {
                // Custom type elements
                w.WriteLine($"{field.PropertyName}[i]?.Encode(writer); ");
            }
            else
            {
                // Primitive elements
                EmitPrimitiveCollectionElementEncode(w, field, elementType);
            }

            w.CloseBrace();
        }

        private static void EmitPrimitiveCollectionElementEncode(IndentedWriter w, ResolvedField field, string elementType)
        {
            switch (elementType)
            {
                case "string":
                    w.WriteLine($"writer.WriteCharacterString(UniversalTagNumber.GeneralString, {field.PropertyName}[i]);");
                    break;
                case "int":
                    w.WriteLine($"writer.WriteInteger({field.PropertyName}[i]);");
                    break;
                case "Oid":
                    w.WriteLine($"writer.WriteObjectIdentifier({field.PropertyName}[i]?.Value);");
                    break;
                default:
                    if (field.Encoding.EnumType != null)
                    {
                        w.WriteLine($"writer.WriteInteger((long){field.PropertyName}[i]);");
                    }
                    else
                    {
                        w.WriteLine($"writer.WriteEncodedValue({field.PropertyName}[i].Span);");
                    }
                    break;
            }
        }

        // ─── Field decoding ─────────────────────────────────────────────

        private static void EmitFieldDecode(IndentedWriter w, ResolvedField field, ResolvedType type)
        {
            if (field.IsOptional)
            {
                if (field.Encoding.TagNumber.HasValue)
                {
                    string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value})";
                    w.WriteLine($"if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue({tag}))");
                }
                else if (field.Encoding.Kind == FieldKind.CustomType)
                {
                    w.WriteLine($"if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))");
                }
                else
                {
                    w.WriteLine("if (sequenceReader.HasData)");
                }

                w.OpenBrace();
            }

            if (field.Encoding.TagNumber.HasValue)
            {
                if (field.Encoding.IsImplicit)
                {
                    EmitImplicitFieldDecode(w, field);
                }
                else
                {
                    string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber.Value})";
                    w.WriteLine($"explicitReader = sequenceReader.ReadSequence({tag});");
                    EmitFieldValueDecode(w, field, "explicitReader");
                    w.WriteLine();
                    w.WriteLine("explicitReader.ThrowIfNotEmpty();");
                }
            }
            else
            {
                EmitFieldValueDecode(w, field, "sequenceReader");
            }

            if (field.IsOptional)
            {
                w.CloseBrace();
            }

            w.WriteLine();
        }

        private static void EmitImplicitFieldDecode(IndentedWriter w, ResolvedField field)
        {
            string tag = $"new Asn1Tag(TagClass.ContextSpecific, {field.Encoding.TagNumber!.Value})";

            switch (field.Encoding.Kind)
            {
                case FieldKind.OctetString:
                    w.WriteLine();
                    w.WriteLine($"if (sequenceReader.TryReadPrimitiveOctetStringBytes({tag}, out ReadOnlyMemory<byte> tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    w.CloseBrace();
                    w.WriteLine("else");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = sequenceReader.ReadOctetString({tag});");
                    w.CloseBrace();
                    break;

                case FieldKind.BitString:
                    w.WriteLine($"decoded.{field.PropertyName} = sequenceReader.ReadBitString({tag}, out _);");
                    break;

                default:
                    // Fallback for other implicit types
                    w.WriteLine($"explicitReader = sequenceReader.ReadSequence({tag});");
                    EmitFieldValueDecode(w, field, "explicitReader");
                    w.WriteLine("explicitReader.ThrowIfNotEmpty();");
                    break;
            }
        }

        private static void EmitFieldValueDecode(IndentedWriter w, ResolvedField field, string readerVar)
        {
            switch (field.Encoding.Kind)
            {
                case FieldKind.Integer:
                    w.WriteLine();
                    w.WriteLine($"if (!{readerVar}.TryReadInt32(out int tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"{readerVar}.ThrowIfNotEmpty();");
                    w.CloseBrace();
                    w.WriteLine();
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    break;

                case FieldKind.IntegerEnum:
                    string enumTypeInt = field.Encoding.EnumType ?? "int";
                    w.WriteLine();
                    w.WriteLine($"if (!{readerVar}.TryReadInt32(out int tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"{readerVar}.ThrowIfNotEmpty();");
                    w.CloseBrace();
                    w.WriteLine();
                    w.WriteLine($"decoded.{field.PropertyName} = ({enumTypeInt})tmp{field.PropertyName};");
                    break;

                case FieldKind.BitString:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadBitString(out _);");
                    break;

                case FieldKind.BitStringFlagsEnum:
                    string flagsEnum = field.Encoding.EnumType ?? "int";
                    w.WriteLine();
                    w.WriteLine($"if ({readerVar}.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = ({flagsEnum})tmp{field.PropertyName}.AsLong();");
                    w.CloseBrace();
                    w.WriteLine("else");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = ({flagsEnum}){readerVar}.ReadBitString(out _).AsLong();");
                    w.CloseBrace();
                    break;

                case FieldKind.OctetString:
                    w.WriteLine();
                    w.WriteLine($"if ({readerVar}.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    w.CloseBrace();
                    w.WriteLine("else");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadOctetString();");
                    w.CloseBrace();
                    break;

                case FieldKind.GeneralString:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.GeneralString);");
                    break;

                case FieldKind.UTF8String:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.UTF8String);");
                    break;

                case FieldKind.IA5String:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.IA5String);");
                    break;

                case FieldKind.PrintableString:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.PrintableString);");
                    break;

                case FieldKind.VisibleString:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.VisibleString);");
                    break;

                case FieldKind.T61String:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.T61String);");
                    break;

                case FieldKind.BMPString:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadCharacterString(UniversalTagNumber.BMPString);");
                    break;

                case FieldKind.GeneralizedTime:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadGeneralizedTime();");
                    break;

                case FieldKind.UtcTime:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadUtcTime();");
                    break;

                case FieldKind.ObjectIdentifier:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadObjectIdentifier();");
                    break;

                case FieldKind.Boolean:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadBoolean();");
                    break;

                case FieldKind.CustomType:
                    string refName = field.Encoding.ReferencedTypeName ?? field.CSharpType;
                    w.WriteLine($"{refName}.Decode<{refName}>({readerVar}, out {refName} tmp{field.PropertyName});");
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    break;

                case FieldKind.SequenceOf:
                case FieldKind.SetOf:
                    EmitCollectionDecode(w, field, readerVar);
                    break;

                case FieldKind.Enumerated:
                    w.WriteLine();
                    w.WriteLine($"if (!{readerVar}.TryReadInt32(out int tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"{readerVar}.ThrowIfNotEmpty();");
                    w.CloseBrace();
                    w.WriteLine();
                    if (!string.IsNullOrEmpty(field.Encoding.EnumType))
                    {
                        w.WriteLine($"decoded.{field.PropertyName} = ({field.Encoding.EnumType})tmp{field.PropertyName};");
                    }
                    else
                    {
                        w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    }
                    break;

                case FieldKind.Any:
                    if (field.IsOptional)
                    {
                        w.WriteLine($"if ({readerVar}.HasData)");
                        w.OpenBrace();
                        w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadEncodedValue();");
                        w.CloseBrace();
                    }
                    else
                    {
                        w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadEncodedValue();");
                    }
                    break;

                case FieldKind.BigInteger:
                    w.WriteLine($"decoded.{field.PropertyName} = {readerVar}.ReadInteger();");
                    break;
            }
        }

        private static void EmitCollectionDecode(IndentedWriter w, ResolvedField field, string readerVar)
        {
            string elementType = field.CollectionElementType ?? "object";

            w.WriteLine($"// Decode SEQUENCE OF for {field.PropertyName}");
            w.OpenBrace();
            w.WriteLine($"collectionReader = {readerVar}.ReadSequence();");

            if (field.Encoding.ReferencedTypeName != null)
            {
                // Custom type collection
                string refName = field.Encoding.ReferencedTypeName;
                w.WriteLine($"var tmpList = new List<{refName}>();");
                w.WriteLine($"{refName} tmpItem;");
                w.WriteLine();
                w.WriteLine("while (collectionReader.HasData)");
                w.OpenBrace();
                w.WriteLine($"{refName}.Decode<{refName}>(collectionReader, out {refName} tmp);");
                w.WriteLine("tmpItem = tmp; ");
                w.WriteLine("tmpList.Add(tmpItem);");
                w.CloseBrace();
            }
            else
            {
                // Primitive collection
                w.WriteLine($"var tmpList = new List<{elementType}>();");

                if (elementType == "string")
                {
                    w.WriteLine("string tmpItem;");
                    w.WriteLine();
                    w.WriteLine("while (collectionReader.HasData)");
                    w.OpenBrace();
                    w.WriteLine("tmpItem = collectionReader.ReadCharacterString(UniversalTagNumber.GeneralString); ");
                    w.WriteLine("tmpList.Add(tmpItem);");
                    w.CloseBrace();
                }
                else if (elementType == "int")
                {
                    w.WriteLine();
                    w.WriteLine("while (collectionReader.HasData)");
                    w.OpenBrace();
                    w.WriteLine("if (!collectionReader.TryReadInt32(out int tmp))");
                    w.OpenBrace();
                    w.WriteLine("throw new CryptographicException();");
                    w.CloseBrace();
                    w.WriteLine("tmpList.Add(tmp);");
                    w.CloseBrace();
                }
                else if (elementType == "Oid")
                {
                    w.WriteLine();
                    w.WriteLine("while (collectionReader.HasData)");
                    w.OpenBrace();
                    w.WriteLine("tmpList.Add(collectionReader.ReadObjectIdentifier());");
                    w.CloseBrace();
                }
                else if (field.Encoding.EnumType != null)
                {
                    string enumName = field.Encoding.EnumType;
                    w.WriteLine();
                    w.WriteLine("while (collectionReader.HasData)");
                    w.OpenBrace();
                    w.WriteLine($"if (!collectionReader.TryReadInt32(out {enumName} tmp))");
                    w.OpenBrace();
                    w.WriteLine("throw new CryptographicException();");
                    w.CloseBrace();
                    w.WriteLine("tmpList.Add(tmp);");
                    w.CloseBrace();
                }
                else
                {
                    w.WriteLine();
                    w.WriteLine("while (collectionReader.HasData)");
                    w.OpenBrace();
                    w.WriteLine("tmpList.Add(collectionReader.ReadEncodedValue());");
                    w.CloseBrace();
                }
            }

            w.WriteLine();
            w.WriteLine($"decoded.{field.PropertyName} = tmpList.ToArray();");
            w.CloseBrace();
        }

        private static void EmitChoiceFieldDecode(IndentedWriter w, ResolvedField field)
        {
            switch (field.Encoding.Kind)
            {
                case FieldKind.CustomType:
                    string refName = field.Encoding.ReferencedTypeName ?? field.CSharpType;
                    w.WriteLine($"{refName}.Decode<{refName}>(explicitReader, out {refName} tmp{field.PropertyName});");
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    break;

                case FieldKind.OctetString:
                    w.WriteLine($"if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp{field.PropertyName}))");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = tmp{field.PropertyName};");
                    w.CloseBrace();
                    w.WriteLine("else");
                    w.OpenBrace();
                    w.WriteLine($"decoded.{field.PropertyName} = explicitReader.ReadOctetString();");
                    w.CloseBrace();
                    break;

                default:
                    EmitFieldValueDecode(w, field, "explicitReader");
                    break;
            }
        }

        // ─── Shared output helpers ───────────────────────────────────────

        private static void WriteHeader(IndentedWriter w)
        {
            w.WriteRaw("// -----------------------------------------------------------------------");
            w.WriteRaw("// Licensed to The .NET Foundation under one or more agreements.");
            w.WriteRaw("// The .NET Foundation licenses this file to you under the MIT license.");
            w.WriteRaw("// -----------------------------------------------------------------------");
            w.WriteRaw("");
            w.WriteRaw("// This is a generated file.");
            w.WriteRaw("// The generation template has been modified from .NET Runtime implementation");
            w.WriteRaw("");
        }

        private static void WriteUsings(IndentedWriter w, bool hasCollections, bool isChoice)
        {
            w.WriteRaw("using System;");

            if (hasCollections)
            {
                w.WriteRaw("using System.Collections.Generic;");
            }

            if (isChoice)
            {
                w.WriteRaw("using System.Runtime.InteropServices;");
            }

            w.WriteRaw("using System.Security.Cryptography;");
            w.WriteRaw("using System.Security.Cryptography.Asn1;");
            w.WriteRaw("using Kerberos.NET.Crypto;");
            w.WriteRaw("using Kerberos.NET.Asn1;");
        }

        private static void WriteAsnComment(IndentedWriter w, ResolvedType type)
        {
            // Write the original ASN.1 definition as a comment block
            var assignment = type.Assignment;
            w.WriteLine("/*");

            if (type.Kind == ResolvedTypeKind.InheritedSequence)
            {
                var taggedAlias = assignment.Type as AsnTaggedTypeAlias;

                if (taggedAlias != null && taggedAlias.Tag != null)
                {
                    w.WriteRawIndented($"    {assignment.Name} ::= [{taggedAlias.Tag.Class.ToString().ToUpperInvariant()} {taggedAlias.Tag.Number}] {taggedAlias.ReferencedName}");
                }
                else
                {
                    w.WriteRawIndented($"    {assignment.Name} ::= {(assignment.Type as AsnTaggedTypeAlias)?.ReferencedName ?? ""}");
                }
            }
            else if (type.Kind == ResolvedTypeKind.CollectionWrapper)
            {
                var coll = assignment.Type as AsnCollectionType;
                string elementName = "";

                if (coll?.ElementType is AsnReferencedType refElem)
                {
                    elementName = refElem.ReferencedName;
                }

                w.WriteRawIndented($"    {assignment.Name} ::= SEQUENCE OF {elementName}");
            }
            else
            {
                // Simplified - just show the type name
                string keyword = type.IsChoice ? "CHOICE" : "SEQUENCE";
                string appTag = type.ApplicationTag.HasValue
                    ? $"[APPLICATION {type.ApplicationTag.Value}] "
                    : "";

                w.WriteRawIndented($"    {assignment.Name} ::= {appTag}{keyword} {{");

                if (assignment.Type is AsnSequenceType seq)
                {
                    foreach (var field in seq.Fields)
                    {
                        string opt = field.Optional ? " OPTIONAL" : "";
                        string tagStr = field.Type.Tag != null ? $"[{field.Type.Tag.Number}] " : "";
                        w.WriteRawIndented($"            {field.Name,-24}{tagStr}{GetAsnTypeName(field.Type)}{opt}");
                    }
                }
                else if (assignment.Type is AsnChoiceType ch)
                {
                    foreach (var alt in ch.Alternatives)
                    {
                        string tagStr = alt.Type.Tag != null ? $"[{alt.Type.Tag.Number}] " : "";
                        w.WriteRawIndented($"            {alt.Name,-24}{tagStr}{GetAsnTypeName(alt.Type)}");
                    }
                }

                w.WriteRawIndented("    }");
            }

            w.WriteLine(" */");
            w.WriteLine();
        }

        private static string GetAsnTypeName(AsnType type)
        {
            if (type is AsnPrimitiveType prim)
            {
                return prim.Kind.ToString().ToUpperInvariant();
            }

            if (type is AsnReferencedType refType)
            {
                return refType.ReferencedName;
            }

            if (type is AsnCollectionType coll)
            {
                string prefix = coll.IsSetOf ? "SET OF " : "SEQUENCE OF ";
                return prefix + GetAsnTypeName(coll.ElementType);
            }

            if (type is AsnAnyType)
            {
                return "ANY";
            }

            return "UNKNOWN";
        }

        private static void WriteProperties(IndentedWriter w, List<ResolvedField> fields)
        {
            foreach (var field in fields)
            {
                w.WriteLine($"public {field.CSharpType} {field.PropertyName} {{ get; set; }}");
                w.WriteLine();
            }
        }

        private static void WriteObsoleteAliases(IndentedWriter w, List<ResolvedField> fields)
        {
            foreach (var field in fields)
            {
                if (!string.IsNullOrEmpty(field.ObsoleteAliasName))
                {
                    w.WriteLine($"[Obsolete(\"Use {field.PropertyName} instead\")]");
                    w.WriteLine($"public {field.CSharpType} {field.ObsoleteAliasName} {{ get => {field.PropertyName}; set => {field.PropertyName} = value; }}");
                    w.WriteLine();
                }
            }
        }

        // ─── IndentedWriter ─────────────────────────────────────────────

        private class IndentedWriter
        {
            private readonly StringBuilder sb = new StringBuilder();
            private int indent;

            public void WriteLine(string line)
            {
                sb.Append(new string(' ', indent * 4));
                sb.AppendLine(line);
            }

            public void WriteLine()
            {
                sb.AppendLine();
            }

            /// <summary>
            /// Write a line with no indentation (for file-level content like headers/usings).
            /// </summary>
            public void WriteRaw(string line)
            {
                sb.AppendLine(line);
            }

            /// <summary>
            /// Write a line at the current indent level plus additional raw content.
            /// Used for ASN.1 comment blocks that have their own internal formatting.
            /// </summary>
            public void WriteRawIndented(string line)
            {
                sb.Append(new string(' ', indent * 4));
                sb.AppendLine(line);
            }

            public void OpenBrace()
            {
                WriteLine("{");
                indent++;
            }

            public void CloseBrace()
            {
                indent--;
                WriteLine("}");
            }

            /// <summary>
            /// Close brace with a suffix (e.g., "};").
            /// </summary>
            public void CloseBrace(string suffix)
            {
                indent--;
                WriteLine("}" + suffix);
            }

            public override string ToString()
            {
                return sb.ToString();
            }
        }
    }
}
