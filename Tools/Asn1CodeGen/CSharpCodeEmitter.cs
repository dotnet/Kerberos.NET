// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Asn1CodeGen
{
    public class TypeConfig
    {
        public string CSharpName { get; set; }
        public string Namespace { get; set; } = "Kerberos.NET.Entities";
        public int? ApplicationTag { get; set; }
        public string InheritsFrom { get; set; }
        public Dictionary<string, FieldConfig> Fields { get; set; } = new();
    }

    public class FieldConfig
    {
        public string CSharpName { get; set; }
        public string BackingType { get; set; }
        public string EnumType { get; set; }
        public bool TreatAsEnum { get; set; }
    }

    public class EmitterConfig
    {
        public Dictionary<string, TypeConfig> Types { get; set; } = new();
    }

    public class CSharpCodeEmitter
    {
        private readonly List<Asn1Module> modules;
        private readonly EmitterConfig config;

        // Merged alias table from all modules
        private readonly Dictionary<string, Asn1Type> aliases = new();

        // Module-level tag defaults
        private readonly Dictionary<string, TagDefault> moduleTagDefaults = new();

        // Type assignments that are SEQUENCE OF with inline SEQUENCE
        // When referenced as a field, these should be treated as ClassName[]
        private readonly HashSet<string> sequenceOfInlineTypes = new();

        public CSharpCodeEmitter(List<Asn1Module> modules, EmitterConfig config = null)
        {
            this.modules = modules;
            this.config = config ?? new EmitterConfig();
            this.BuildAliasTable();
        }

        // Backward-compat single-module constructor
        public CSharpCodeEmitter(Asn1Module module, EmitterConfig config = null)
            : this(new List<Asn1Module> { module }, config)
        {
        }

        private void BuildAliasTable()
        {
            foreach (var module in this.modules)
            {
                foreach (var kvp in module.TypeAliases)
                {
                    this.aliases[kvp.Key] = kvp.Value;
                }

                // Track SEQUENCE OF SEQUENCE { ... } type assignments
                foreach (var assignment in module.TypeAssignments)
                {
                    var type = assignment.Type;

                    // Unwrap APPLICATION tag if present
                    if (type is Asn1TaggedType tagged && tagged.TagClass == TagClass.Application)
                    {
                        type = tagged.InnerType;
                    }

                    if (type is Asn1SequenceOfType seqOf && seqOf.ElementType is Asn1SequenceType)
                    {
                        this.sequenceOfInlineTypes.Add(assignment.Name);
                    }
                }

                this.moduleTagDefaults[module.Name] = module.TagDefault;
            }
        }

        public Dictionary<string, string> EmitAll()
        {
            var files = new Dictionary<string, string>();

            foreach (var module in this.modules)
            {
                foreach (var assignment in module.TypeAssignments)
                {
                    var tc = this.GetTypeConfig(assignment.Name);
                    var className = tc.CSharpName ?? ToPascalCase(assignment.Name);

                    // Handle SEQUENCE OF with inline SEQUENCE:
                    // e.g. AuthorizationData ::= SEQUENCE OF SEQUENCE { ... }
                    var emitType = this.UnwrapApplicationTag(assignment.Type, tc);

                    if (emitType is Asn1SequenceOfType seqOf && seqOf.ElementType is Asn1SequenceType innerSeq)
                    {
                        // Emit the inner SEQUENCE as the class, the outer is just TypeName[]
                        var innerAssignment = new Asn1TypeAssignment
                        {
                            Name = assignment.Name,
                            Type = innerSeq,
                            Comment = assignment.Comment
                        };

                        var code = this.EmitTypeAssignment(innerAssignment, module);
                        files[className + ".generated.cs"] = code;
                    }
                    else
                    {
                        var code = this.EmitTypeAssignment(assignment, module);
                        files[className + ".generated.cs"] = code;
                    }
                }
            }

            return files;
        }

        private Asn1Type UnwrapApplicationTag(Asn1Type type, TypeConfig tc)
        {
            if (type is Asn1TaggedType topTag && topTag.TagClass == TagClass.Application)
            {
                if (!tc.ApplicationTag.HasValue)
                {
                    tc.ApplicationTag = topTag.TagNumber;
                }

                return topTag.InnerType;
            }

            return type;
        }

        public string EmitTypeAssignment(Asn1TypeAssignment assignment, Asn1Module module = null)
        {
            var tc = this.GetTypeConfig(assignment.Name);
            var className = tc.CSharpName ?? ToPascalCase(assignment.Name);
            var ns = tc.Namespace;

            var emitType = this.UnwrapApplicationTag(assignment.Type, tc);

            // Determine what usings we need
            var usings = new HashSet<string>
            {
                "System",
                "System.Security.Cryptography",
                "System.Security.Cryptography.Asn1",
                "Kerberos.NET.Crypto",
                "Kerberos.NET.Asn1",
            };

            if (this.NeedsCollections(emitType))
            {
                usings.Add("System.Collections.Generic");
            }

            if (emitType is Asn1ChoiceType)
            {
                usings.Add("System.Runtime.InteropServices");
            }

            var sb = new StringBuilder();
            this.EmitHeader(sb);

            foreach (var u in usings.OrderBy(x => x))
            {
                sb.AppendLine($"using {u};");
            }

            sb.AppendLine();
            sb.AppendLine($"namespace {ns}");
            sb.AppendLine("{");

            if (tc.InheritsFrom != null)
            {
                this.EmitInheritedSequence(sb, assignment, tc);
            }
            else if (emitType is Asn1ChoiceType choice)
            {
                this.EmitChoiceType(sb, assignment, choice, tc, className, module);
            }
            else if (emitType is Asn1SequenceType seq)
            {
                this.EmitSequenceType(sb, assignment, seq, tc, className, module);
            }

            sb.AppendLine("}");
            return sb.ToString();
        }

        private void EmitHeader(StringBuilder sb)
        {
            sb.AppendLine("// -----------------------------------------------------------------------");
            sb.AppendLine("// Licensed to The .NET Foundation under one or more agreements.");
            sb.AppendLine("// The .NET Foundation licenses this file to you under the MIT license.");
            sb.AppendLine("// -----------------------------------------------------------------------");
            sb.AppendLine();
            sb.AppendLine("// This is a generated file.");
            sb.AppendLine("// The generation template has been modified from .NET Runtime implementation");
            sb.AppendLine();
        }

        #region Type Alias Resolution

        /// <summary>
        /// Resolve a referenced type name through the alias chain to a concrete Asn1Type.
        /// </summary>
        private Asn1Type ResolveAlias(string name)
        {
            var visited = new HashSet<string>();

            while (this.aliases.TryGetValue(name, out var aliased))
            {
                if (!visited.Add(name))
                {
                    break; // cycle
                }

                if (aliased is Asn1ReferencedType refType)
                {
                    name = refType.ReferenceName;
                }
                else
                {
                    return aliased;
                }
            }

            return null;
        }

        /// <summary>
        /// Resolve a field's type, chasing through aliases and returning the resolved
        /// Asn1Type for encode/decode code generation.
        /// </summary>
        private Asn1Type ResolveFieldType(Asn1Type type)
        {
            if (type is Asn1ReferencedType refType)
            {
                // SEQUENCE OF SEQUENCE { ... } type assignments should be treated as arrays
                if (this.sequenceOfInlineTypes.Contains(refType.ReferenceName))
                {
                    return new Asn1SequenceOfType
                    {
                        ElementType = new Asn1ReferencedType { ReferenceName = refType.ReferenceName }
                    };
                }

                var resolved = this.ResolveAlias(refType.ReferenceName);

                if (resolved != null)
                {
                    return resolved;
                }
            }

            return type;
        }

        /// <summary>
        /// Check if a referenced type ultimately resolves to a generatable class
        /// (as opposed to a builtin type alias).
        /// </summary>
        private bool IsGeneratableReference(string name)
        {
            var resolved = this.ResolveAlias(name);
            return resolved == null; // no alias means it's a real type with its own class
        }

        #endregion

        #region Tagging

        private TaggingMode GetEffectiveTaggingMode(Asn1TaggedType tagged, Asn1Module module)
        {
            if (tagged.Mode != TaggingMode.Default)
            {
                return tagged.Mode;
            }

            // Use module default
            if (module != null)
            {
                return module.TagDefault == TagDefault.Implicit
                    ? TaggingMode.Implicit
                    : TaggingMode.Explicit;
            }

            return TaggingMode.Explicit;
        }

        private bool IsImplicitTag(Asn1Field field, Asn1Module module)
        {
            if (field.Type is Asn1TaggedType tagged)
            {
                return this.GetEffectiveTaggingMode(tagged, module) == TaggingMode.Implicit;
            }

            return false;
        }

        #endregion

        #region Sequence Type

        private void EmitSequenceType(
            StringBuilder sb,
            Asn1TypeAssignment assignment,
            Asn1SequenceType seq,
            TypeConfig tc,
            string className,
            Asn1Module module)
        {
            bool hasAppTag = tc.ApplicationTag.HasValue;

            sb.AppendLine($"    public partial class {className}");
            sb.AppendLine("    {");

            if (!string.IsNullOrEmpty(assignment.Comment))
            {
                sb.AppendLine("        /*");
                foreach (var line in assignment.Comment.Split('\n'))
                {
                    sb.AppendLine($"          {line.TrimEnd()}");
                }

                sb.AppendLine("         */");
            }

            sb.AppendLine("    ");

            // Properties
            foreach (var field in seq.Fields)
            {
                var fc = this.GetFieldConfig(tc, field.Name);
                var propName = fc.CSharpName ?? ToPascalCase(field.Name);
                var propType = this.GetCSharpType(field, fc);

                sb.AppendLine($"        public {propType} {propName} {{ get; set; }}");
                sb.AppendLine("  ");
            }

            // Encoding
            sb.AppendLine("        // Encoding methods");

            if (!hasAppTag)
            {
                sb.AppendLine("        public ReadOnlyMemory<byte> Encode()");
                sb.AppendLine("        {");
                sb.AppendLine("            var writer = new AsnWriter(AsnEncodingRules.DER);");
                sb.AppendLine();
                sb.AppendLine("            Encode(writer);");
                sb.AppendLine();
                sb.AppendLine("            return writer.EncodeAsMemory();");
                sb.AppendLine("        }");
                sb.AppendLine(" ");
            }

            sb.AppendLine("        internal void Encode(AsnWriter writer)");
            sb.AppendLine("        {");
            sb.AppendLine(hasAppTag
                ? "            EncodeApplication(writer, ApplicationTag);"
                : "            Encode(writer, Asn1Tag.Sequence);");
            sb.AppendLine("        }");
            sb.AppendLine("        ");

            sb.AppendLine("        internal void Encode(AsnWriter writer, Asn1Tag tag)");
            sb.AppendLine("        {");
            sb.AppendLine("            writer.PushSequence(tag);");
            sb.AppendLine("            ");

            foreach (var field in seq.Fields)
            {
                this.EmitFieldEncode(sb, field, tc, module);
            }

            sb.AppendLine("            writer.PopSequence(tag);");
            sb.AppendLine("        }");
            sb.AppendLine("        ");

            sb.AppendLine("        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)");
            sb.AppendLine("        {");
            sb.AppendLine("            writer.PushSequence(tag);");
            sb.AppendLine("            ");
            sb.AppendLine("            this.Encode(writer, Asn1Tag.Sequence);");
            sb.AppendLine("            ");
            sb.AppendLine("            writer.PopSequence(tag);");
            sb.AppendLine("        }       ");
            sb.AppendLine("        ");

            if (hasAppTag)
            {
                int appTagNum = tc.ApplicationTag.Value;
                sb.AppendLine($"        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, {appTagNum});");
                sb.AppendLine("        ");
                sb.AppendLine("        public virtual ReadOnlyMemory<byte> EncodeApplication() ");
                sb.AppendLine("        {");
                sb.AppendLine("          return EncodeApplication(ApplicationTag);");
                sb.AppendLine("        }");
                sb.AppendLine("        ");
                sb.AppendLine($"        public static {className} DecodeApplication(ReadOnlyMemory<byte> encoded)");
                sb.AppendLine("        {");
                sb.AppendLine("            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
                sb.AppendLine();
                sb.AppendLine("            var sequence = reader.ReadSequence(ApplicationTag);");
                sb.AppendLine("          ");
                sb.AppendLine($"            {className} decoded;");
                sb.AppendLine("            Decode(sequence, Asn1Tag.Sequence, out decoded);");
                sb.AppendLine("            sequence.ThrowIfNotEmpty();");
                sb.AppendLine();
                sb.AppendLine("            reader.ThrowIfNotEmpty();");
                sb.AppendLine();
                sb.AppendLine("            return decoded;");
                sb.AppendLine("        }");
                sb.AppendLine("        ");
                sb.AppendLine($"        internal static {className} DecodeApplication<T>(AsnReader reader, out T decoded)");
                sb.AppendLine($"          where T: {className}, new()");
                sb.AppendLine("        {");
                sb.AppendLine("            var sequence = reader.ReadSequence(ApplicationTag);");
                sb.AppendLine("          ");
                sb.AppendLine("            Decode(sequence, Asn1Tag.Sequence, out decoded);");
                sb.AppendLine("            sequence.ThrowIfNotEmpty();");
                sb.AppendLine();
                sb.AppendLine("            reader.ThrowIfNotEmpty();");
                sb.AppendLine();
                sb.AppendLine("            return decoded;");
                sb.AppendLine("        }");
            }
            else
            {
                sb.AppendLine("        public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();");
            }

            sb.AppendLine("         ");
            sb.AppendLine("        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)");
            sb.AppendLine("        {");
            sb.AppendLine("            using (var writer = new AsnWriter(AsnEncodingRules.DER))");
            sb.AppendLine("            {");
            sb.AppendLine("                EncodeApplication(writer, tag);");
            sb.AppendLine();
            sb.AppendLine("                return writer.EncodeAsMemory();");
            sb.AppendLine("            }");
            sb.AppendLine("        }");
            sb.AppendLine("        ");

            // Decode methods
            if (!hasAppTag)
            {
                sb.AppendLine($"        public static {className} Decode(ReadOnlyMemory<byte> data)");
                sb.AppendLine("        {");
                sb.AppendLine("            return Decode(data, AsnEncodingRules.DER);");
                sb.AppendLine("        }");
                sb.AppendLine();
                sb.AppendLine($"        internal static {className} Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
                sb.AppendLine("        {");
                sb.AppendLine("            return Decode(Asn1Tag.Sequence, encoded, ruleSet);");
                sb.AppendLine("        }");
                sb.AppendLine("        ");
            }

            sb.AppendLine($"        internal static {className} Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)");
            sb.AppendLine("        {");
            sb.AppendLine("            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
            sb.AppendLine("            ");
            sb.AppendLine($"            Decode(reader, expectedTag, out {className} decoded);");
            sb.AppendLine("            reader.ThrowIfNotEmpty();");
            sb.AppendLine("            return decoded;");
            sb.AppendLine("        }");
            sb.AppendLine();
            sb.AppendLine($"        internal static {className} Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            sb.AppendLine("        {");
            sb.AppendLine("            AsnReader reader = new AsnReader(encoded, ruleSet);");
            sb.AppendLine("            ");
            sb.AppendLine($"            Decode(reader, expectedTag, out {className} decoded);");
            sb.AppendLine("            reader.ThrowIfNotEmpty();");
            sb.AppendLine("            return decoded;");
            sb.AppendLine("        }");
            sb.AppendLine();

            sb.AppendLine($"        internal static void Decode<T>(AsnReader reader, out T decoded)");
            sb.AppendLine($"          where T: {className}, new()");
            sb.AppendLine("        {");
            sb.AppendLine("            if (reader == null)");
            sb.AppendLine("            {");
            sb.AppendLine("                throw new ArgumentNullException(nameof(reader));");
            sb.AppendLine("            }");
            sb.AppendLine("            ");
            sb.AppendLine(hasAppTag
                ? "            DecodeApplication(reader, out decoded);"
                : "            Decode(reader, Asn1Tag.Sequence, out decoded);");
            sb.AppendLine("        }");
            sb.AppendLine();

            sb.AppendLine($"        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)");
            sb.AppendLine($"          where T: {className}, new()");
            sb.AppendLine("        {");
            sb.AppendLine("            if (reader == null)");
            sb.AppendLine("            {");
            sb.AppendLine("                throw new ArgumentNullException(nameof(reader));");
            sb.AppendLine("            }");
            sb.AppendLine();
            sb.AppendLine("            decoded = new T();");
            sb.AppendLine("            ");
            sb.AppendLine("            AsnReader sequenceReader = reader.ReadSequence(expectedTag);");

            bool needsExplicitReader = seq.Fields.Count > 0;
            bool needsCollectionReader = seq.Fields.Any(f => this.IsSequenceOfField(f) || this.IsSetOfField(f));

            if (needsExplicitReader)
            {
                sb.AppendLine("            AsnReader explicitReader;");
            }

            if (needsCollectionReader)
            {
                sb.AppendLine("            AsnReader collectionReader;");
            }

            sb.AppendLine("            ");

            foreach (var field in seq.Fields)
            {
                this.EmitFieldDecode(sb, field, tc, className, module);
            }

            sb.AppendLine("            sequenceReader.ThrowIfNotEmpty();");
            sb.AppendLine("        }");
            sb.AppendLine("    }");
        }

        #endregion

        #region Choice Type

        private void EmitChoiceType(
            StringBuilder sb,
            Asn1TypeAssignment assignment,
            Asn1ChoiceType choice,
            TypeConfig tc,
            string className,
            Asn1Module module)
        {
            sb.AppendLine($"    public partial class {className}");
            sb.AppendLine("    {");

            if (!string.IsNullOrEmpty(assignment.Comment))
            {
                sb.AppendLine("        /*");
                foreach (var line in assignment.Comment.Split('\n'))
                {
                    sb.AppendLine($"          {line.TrimEnd()}");
                }

                sb.AppendLine("         */");
            }

            sb.AppendLine("    ");

            foreach (var field in choice.Fields)
            {
                var fc = this.GetFieldConfig(tc, field.Name);
                var propName = fc.CSharpName ?? ToPascalCase(field.Name);
                var propType = this.GetChoiceFieldCSharpType(field, fc);
                sb.AppendLine($"        public {propType} {propName} {{ get; set; }}");
                sb.AppendLine("  ");
            }

            // DEBUG tag validation
            sb.AppendLine("#if DEBUG");
            sb.AppendLine($"        static {className}()");
            sb.AppendLine("        {");
            sb.AppendLine("            var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();");
            sb.AppendLine("            Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>");
            sb.AppendLine("            {");
            sb.AppendLine("                if (usedTags.TryGetValue(tag, out string existing))");
            sb.AppendLine("                {");
            sb.AppendLine("                    throw new InvalidOperationException($\"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'\");");
            sb.AppendLine("                }");
            sb.AppendLine();
            sb.AppendLine("                usedTags.Add(tag, fieldName);");
            sb.AppendLine("            };");
            sb.AppendLine("            ");

            foreach (var field in choice.Fields)
            {
                var fc = this.GetFieldConfig(tc, field.Name);
                var propName = fc.CSharpName ?? ToPascalCase(field.Name);
                int tagNum = this.GetTagNumber(field);
                sb.AppendLine($"            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, {tagNum}), \"{propName}\");");
            }

            sb.AppendLine("        }");
            sb.AppendLine("#endif");

            sb.AppendLine("        // Encoding methods");
            sb.AppendLine("        public ReadOnlyMemory<byte> Encode()");
            sb.AppendLine("        {");
            sb.AppendLine("            var writer = new AsnWriter(AsnEncodingRules.DER);");
            sb.AppendLine();
            sb.AppendLine("            Encode(writer);");
            sb.AppendLine();
            sb.AppendLine("            return writer.EncodeAsMemory();");
            sb.AppendLine("        }");
            sb.AppendLine();
            sb.AppendLine("        internal void Encode(AsnWriter writer)");
            sb.AppendLine("        {");
            sb.AppendLine("            bool wroteValue = false; ");
            sb.AppendLine("            ");

            foreach (var field in choice.Fields)
            {
                var fc = this.GetFieldConfig(tc, field.Name);
                var propName = fc.CSharpName ?? ToPascalCase(field.Name);
                int tagNum = this.GetTagNumber(field);
                bool isImplicit = this.IsImplicitTag(field, module);
                var innerType = this.UnwrapTaggedType(field.Type);
                var resolved = this.ResolveFieldType(innerType);

                sb.AppendLine($"            if (Asn1Extension.HasValue({propName}))");
                sb.AppendLine("            {");
                sb.AppendLine("                if (wroteValue)");
                sb.AppendLine("                {");
                sb.AppendLine("                    throw new CryptographicException();");
                sb.AppendLine("                }");
                sb.AppendLine("                ");

                // CHOICE fields always use explicit wrapping (PushSequence/PopSequence)
                sb.AppendLine($"                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                if (this.IsPrimitiveType(resolved))
                {
                    this.EmitFieldEncodeValue(sb, resolved, propName, fc, "                ", true);
                }
                else
                {
                    sb.AppendLine($"                {propName}?.Encode(writer);");
                }
                sb.AppendLine($"                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");

                sb.AppendLine("                wroteValue = true;");
                sb.AppendLine("            }");
            }

            sb.AppendLine("            if (!wroteValue)");
            sb.AppendLine("            {");
            sb.AppendLine("                throw new CryptographicException();");
            sb.AppendLine("            }");
            sb.AppendLine("        }");

            sb.AppendLine("                ");
            sb.AppendLine("        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)");
            sb.AppendLine("        {");
            sb.AppendLine("            using (var writer = new AsnWriter(AsnEncodingRules.DER))");
            sb.AppendLine("            {");
            sb.AppendLine("                writer.PushSequence(tag);");
            sb.AppendLine("                ");
            sb.AppendLine("                this.Encode(writer);");
            sb.AppendLine();
            sb.AppendLine("                writer.PopSequence(tag);");
            sb.AppendLine();
            sb.AppendLine("                return writer.EncodeAsMemory();");
            sb.AppendLine("            }");
            sb.AppendLine("        }");
            sb.AppendLine("        ");

            sb.AppendLine($"        public static {className} Decode(ReadOnlyMemory<byte> data)");
            sb.AppendLine("        {");
            sb.AppendLine("            return Decode(data, AsnEncodingRules.DER);");
            sb.AppendLine("        }");
            sb.AppendLine();
            sb.AppendLine($"        internal static {className} Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)");
            sb.AppendLine("        {");
            sb.AppendLine("            AsnReader reader = new AsnReader(encoded, ruleSet);");
            sb.AppendLine("            ");
            sb.AppendLine($"            Decode(reader, out {className} decoded);");
            sb.AppendLine("            reader.ThrowIfNotEmpty();");
            sb.AppendLine("            return decoded;");
            sb.AppendLine("        }");
            sb.AppendLine();
            sb.AppendLine($"        internal static void Decode<T>(AsnReader reader, out T decoded)");
            sb.AppendLine($"          where T: {className}, new()");
            sb.AppendLine("        {");
            sb.AppendLine("            if (reader == null)");
            sb.AppendLine("            {");
            sb.AppendLine("                throw new ArgumentNullException(nameof(reader));");
            sb.AppendLine("            }");
            sb.AppendLine();
            sb.AppendLine("            decoded = new T();");
            sb.AppendLine("            ");
            sb.AppendLine("            Asn1Tag tag = reader.PeekTag();");
            sb.AppendLine("            AsnReader explicitReader;");
            sb.AppendLine("            ");

            bool first = true;

            foreach (var field in choice.Fields)
            {
                var fc = this.GetFieldConfig(tc, field.Name);
                var propName = fc.CSharpName ?? ToPascalCase(field.Name);
                int tagNum = this.GetTagNumber(field);
                bool isImplicit = this.IsImplicitTag(field, module);
                var innerType = this.UnwrapTaggedType(field.Type);
                var resolved = this.ResolveFieldType(innerType);

                string keyword = first ? "if" : "else if";
                first = false;

                sb.AppendLine($"            {keyword} (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, {tagNum})))");
                sb.AppendLine("            {");

                // CHOICE fields always use explicit wrapping
                sb.AppendLine($"                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                if (this.IsPrimitiveType(resolved))
                {
                    this.EmitFieldDecodeValue(sb, resolved, propName, fc, "                ", false);
                }
                else
                {
                    string typeName = this.GetReferencedTypeName(field);
                    sb.AppendLine($"                {typeName}.Decode<{typeName}>(explicitReader, out {typeName} tmp{propName});");
                    sb.AppendLine($"                decoded.{propName} = tmp{propName};");
                }
                sb.AppendLine("                explicitReader.ThrowIfNotEmpty();");

                sb.AppendLine("            }");
            }

            sb.AppendLine("            else");
            sb.AppendLine("            {");
            sb.AppendLine("                throw new CryptographicException();");
            sb.AppendLine("            }");
            sb.AppendLine("        }");
            sb.AppendLine("    }");
        }

        #endregion

        #region Inherited Sequence

        private void EmitInheritedSequence(StringBuilder sb, Asn1TypeAssignment assignment, TypeConfig tc)
        {
            string className = tc.CSharpName ?? ToPascalCase(assignment.Name);
            string baseName = tc.InheritsFrom;
            int appTag = tc.ApplicationTag ?? 0;

            sb.AppendLine($"    public partial class {className} : {baseName}");
            sb.AppendLine("    {");

            if (!string.IsNullOrEmpty(assignment.Comment))
            {
                sb.AppendLine("        /*");
                foreach (var line in assignment.Comment.Split('\n'))
                {
                    sb.AppendLine($"            {line.TrimEnd()}");
                }

                sb.AppendLine("         */");
            }

            sb.AppendLine("    ");
            sb.AppendLine($"        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, {appTag});");
            sb.AppendLine("        ");
            sb.AppendLine("        public override ReadOnlyMemory<byte> EncodeApplication() ");
            sb.AppendLine("        {");
            sb.AppendLine("          return EncodeApplication(ApplicationTag);");
            sb.AppendLine("        }");
            sb.AppendLine("        ");
            sb.AppendLine($"        public static {className} DecodeApplication(ReadOnlyMemory<byte> encoded)");
            sb.AppendLine("        {");
            sb.AppendLine("            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);");
            sb.AppendLine();
            sb.AppendLine("            var sequence = reader.ReadSequence(ApplicationTag);");
            sb.AppendLine("          ");
            sb.AppendLine($"            {className} decoded;");
            sb.AppendLine("            Decode(sequence, out decoded);");
            sb.AppendLine("            sequence.ThrowIfNotEmpty();");
            sb.AppendLine();
            sb.AppendLine("            reader.ThrowIfNotEmpty();");
            sb.AppendLine();
            sb.AppendLine("            return decoded;");
            sb.AppendLine("        }");
            sb.AppendLine("    }");
        }

        #endregion

        #region Field Encoding

        private void EmitFieldEncode(StringBuilder sb, Asn1Field field, TypeConfig tc, Asn1Module module)
        {
            var fc = this.GetFieldConfig(tc, field.Name);
            var propName = fc.CSharpName ?? ToPascalCase(field.Name);
            int tagNum = this.GetTagNumber(field);
            var innerType = this.UnwrapTaggedType(field.Type);
            var resolved = this.ResolveFieldType(innerType);
            bool hasTag = field.Type is Asn1TaggedType;
            bool isImplicit = this.IsImplicitTag(field, module);

            if (field.Optional)
            {
                sb.AppendLine();
                sb.AppendLine($"            if (Asn1Extension.HasValue({propName}))");
                sb.AppendLine("            {");

                if (hasTag && isImplicit && this.IsPrimitiveType(resolved))
                {
                    this.EmitImplicitPrimitiveEncode(sb, resolved, propName, fc, tagNum, "                ", optional: true);
                }
                else if (hasTag)
                {
                    sb.AppendLine($"                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                    this.EmitFieldEncodeValue(sb, resolved, propName, fc, "                ", true);
                    sb.AppendLine($"                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                }
                else
                {
                    this.EmitFieldEncodeValue(sb, resolved, propName, fc, "                ", true);
                }

                sb.AppendLine("            }");
            }
            else
            {
                if (hasTag && isImplicit && this.IsPrimitiveType(resolved))
                {
                    this.EmitImplicitPrimitiveEncode(sb, resolved, propName, fc, tagNum, "            ");
                }
                else if (hasTag)
                {
                    sb.AppendLine($"            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                    this.EmitFieldEncodeValue(sb, resolved, propName, fc, "            ", false);
                    sb.AppendLine($"            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                }
                else
                {
                    this.EmitFieldEncodeValue(sb, resolved, propName, fc, "            ", false);
                }
            }
        }

        private void EmitImplicitPrimitiveEncode(StringBuilder sb, Asn1Type type, string propName, FieldConfig fc, int tagNum, string indent, bool optional = false)
        {
            string tag = $"new Asn1Tag(TagClass.ContextSpecific, {tagNum})";
            string valueAccess = optional ? ".Value" : "";

            if (type is Asn1OctetStringType)
            {
                sb.AppendLine($"{indent}writer.WriteOctetString({tag}, {propName}{valueAccess}.Span);");
            }
            else if (type is Asn1IntegerType)
            {
                sb.AppendLine($"{indent}writer.WriteInteger({tag}, {propName}{valueAccess});");
            }
            else if (type is Asn1BitStringType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}writer.WriteBitString({tag}, {propName}.AsReadOnlySpan());");
                }
                else
                {
                    sb.AppendLine($"{indent}writer.WriteBitString({tag}, {propName}{valueAccess}.Span);");
                }
            }
            else
            {
                // fallback to explicit
                sb.AppendLine($"{indent}writer.PushSequence({tag});");
                this.EmitFieldEncodeValue(sb, type, propName, fc, indent, false);
                sb.AppendLine($"{indent}writer.PopSequence({tag});");
            }
        }

        private void EmitFieldEncodeValue(StringBuilder sb, Asn1Type type, string propName, FieldConfig fc, string indent, bool optional)
        {
            // BackingType override — treat as referenced type for encode
            if (!string.IsNullOrEmpty(fc.BackingType) && !fc.TreatAsEnum
                && !fc.BackingType.EndsWith("[]") && !fc.BackingType.StartsWith("ReadOnlyMemory")
                && fc.BackingType != "string" && fc.BackingType != "Oid" && fc.BackingType != "int"
                && fc.BackingType != "int?" && fc.BackingType != "bool")
            {
                sb.AppendLine($"{indent}{propName}?.Encode(writer);");
                return;
            }

            if (type is Asn1IntegerType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}writer.WriteInteger((long){propName});");
                }
                else
                {
                    string valueAccess = optional ? ".Value" : "";
                    sb.AppendLine($"{indent}writer.WriteInteger({propName}{valueAccess});");
                }
            }
            else if (type is Asn1OctetStringType)
            {
                sb.AppendLine(optional
                    ? $"{indent}writer.WriteOctetString({propName}.Value.Span);"
                    : $"{indent}writer.WriteOctetString({propName}.Span);");
            }
            else if (type is Asn1BitStringType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}writer.WriteBitString({propName}.AsReadOnlySpan());");
                }
                else
                {
                    string valueAccess = optional ? ".Value" : "";
                    sb.AppendLine($"{indent}writer.WriteBitString({propName}{valueAccess}.Span);");
                }
            }
            else if (type is Asn1BooleanType)
            {
                sb.AppendLine($"{indent}writer.WriteBoolean({propName});");
            }
            else if (type is Asn1NullType)
            {
                sb.AppendLine($"{indent}writer.WriteNull();");
            }
            else if (type is Asn1ObjectIdentifierType)
            {
                sb.AppendLine($"{indent}writer.WriteObjectIdentifier({propName});");
            }
            else if (type is Asn1EnumeratedType)
            {
                sb.AppendLine($"{indent}writer.WriteEnumeratedValue({propName});");
            }
            else if (type is Asn1GeneralizedTimeType)
            {
                string valueAccess = optional ? ".Value" : "";
                sb.AppendLine($"{indent}writer.WriteGeneralizedTime({propName}{valueAccess});");
            }
            else if (type is Asn1UtcTimeType)
            {
                string valueAccess = optional ? ".Value" : "";
                sb.AppendLine($"{indent}writer.WriteUtcTime({propName}{valueAccess});");
            }
            else if (type is Asn1StringType strType)
            {
                string utn = GetUniversalTagNumber(strType.Kind);
                sb.AppendLine($"{indent}writer.WriteCharacterString(UniversalTagNumber.{utn}, {propName});");
            }
            else if (type is Asn1SequenceOfType seqOf)
            {
                sb.AppendLine($"{indent}writer.PushSequence();");
                sb.AppendLine($"{indent}");
                sb.AppendLine($"{indent}for (int i = 0; i < {propName}.Length; i++)");
                sb.AppendLine($"{indent}{{");
                this.EmitSequenceOfElementEncode(sb, seqOf.ElementType, propName, fc, indent + "    ");
                sb.AppendLine($"{indent}}}");
                sb.AppendLine();
                sb.AppendLine($"{indent}writer.PopSequence();");
            }
            else if (type is Asn1ReferencedType)
            {
                sb.AppendLine($"{indent}{propName}?.Encode(writer);");
            }
            else if (type is Asn1AnyType)
            {
                sb.AppendLine(optional
                    ? $"{indent}writer.WriteEncodedValue({propName}.Value.Span);"
                    : $"{indent}writer.WriteEncodedValue({propName}.Span);");
            }
        }

        private void EmitSequenceOfElementEncode(StringBuilder sb, Asn1Type elementType, string propName, FieldConfig fc, string indent)
        {
            var resolved = this.ResolveFieldType(elementType);

            if (resolved is Asn1OctetStringType)
            {
                sb.AppendLine($"{indent}writer.WriteOctetString({propName}[i].Span); ");
            }
            else if (resolved is Asn1IntegerType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}writer.WriteInteger((long){propName}[i]); ");
                }
                else
                {
                    sb.AppendLine($"{indent}writer.WriteInteger({propName}[i]); ");
                }
            }
            else if (resolved is Asn1StringType strType)
            {
                string utn = GetUniversalTagNumber(strType.Kind);
                sb.AppendLine($"{indent}writer.WriteCharacterString(UniversalTagNumber.{utn}, {propName}[i]); ");
            }
            else if (resolved is Asn1ObjectIdentifierType)
            {
                sb.AppendLine($"{indent}writer.WriteObjectIdentifier({propName}[i]); ");
            }
            else if (resolved is Asn1ReferencedType || elementType is Asn1ReferencedType)
            {
                sb.AppendLine($"{indent}{propName}[i]?.Encode(writer); ");
            }
            else
            {
                sb.AppendLine($"{indent}{propName}[i]?.Encode(writer); ");
            }
        }

        #endregion

        #region Field Decoding

        private void EmitFieldDecode(StringBuilder sb, Asn1Field field, TypeConfig tc, string className, Asn1Module module)
        {
            var fc = this.GetFieldConfig(tc, field.Name);
            var propName = fc.CSharpName ?? ToPascalCase(field.Name);
            int tagNum = this.GetTagNumber(field);
            var innerType = this.UnwrapTaggedType(field.Type);
            var resolved = this.ResolveFieldType(innerType);
            bool hasTag = field.Type is Asn1TaggedType;
            bool isImplicit = this.IsImplicitTag(field, module);

            if (field.Optional)
            {
                sb.AppendLine($"            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, {tagNum})))");
                sb.AppendLine("            {");

                if (hasTag && isImplicit && this.IsPrimitiveType(resolved))
                {
                    this.EmitImplicitPrimitiveDecode(sb, resolved, propName, fc, tagNum, "                ");
                }
                else if (hasTag)
                {
                    sb.AppendLine($"                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));                ");
                    sb.AppendLine("            ");
                    this.EmitFieldDecodeValue(sb, resolved, propName, fc, "                ", true);
                    sb.AppendLine("                explicitReader.ThrowIfNotEmpty();");
                }

                sb.AppendLine("            }");
                sb.AppendLine();
            }
            else
            {
                if (hasTag && isImplicit && this.IsPrimitiveType(resolved))
                {
                    this.EmitImplicitPrimitiveDecode(sb, resolved, propName, fc, tagNum, "            ");
                    sb.AppendLine();
                }
                else if (hasTag)
                {
                    sb.AppendLine($"            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, {tagNum}));");
                    sb.AppendLine();
                    this.EmitFieldDecodeValue(sb, resolved, propName, fc, "            ", false);
                    sb.AppendLine();
                    sb.AppendLine("            explicitReader.ThrowIfNotEmpty();");
                    sb.AppendLine();
                }
                else
                {
                    this.EmitFieldDecodeValue(sb, resolved, propName, fc, "            ", false, "sequenceReader");
                }
            }
        }

        private void EmitImplicitPrimitiveDecode(StringBuilder sb, Asn1Type type, string propName, FieldConfig fc, int tagNum, string indent)
        {
            string tag = $"new Asn1Tag(TagClass.ContextSpecific, {tagNum})";

            if (type is Asn1OctetStringType)
            {
                sb.AppendLine($"{indent}if (sequenceReader.TryReadPrimitiveOctetStringBytes({tag}, out ReadOnlyMemory<byte> tmp{propName}))");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    decoded.{propName} = tmp{propName};");
                sb.AppendLine($"{indent}}}");
                sb.AppendLine($"{indent}else");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    decoded.{propName} = sequenceReader.ReadOctetString({tag});");
                sb.AppendLine($"{indent}}}");
            }
            else if (type is Asn1BitStringType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}if (sequenceReader.TryReadPrimitiveBitStringValue({tag}, out _, out ReadOnlyMemory<byte> tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = ({fc.EnumType})tmp{propName}.AsLong();");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}else");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = ({fc.EnumType})sequenceReader.ReadBitString({tag}, out _).AsLong();");
                    sb.AppendLine($"{indent}}}");
                }
                else
                {
                    sb.AppendLine($"{indent}if (sequenceReader.TryReadPrimitiveBitStringValue({tag}, out _, out ReadOnlyMemory<byte> tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = tmp{propName};");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}else");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = sequenceReader.ReadBitString({tag}, out _);");
                    sb.AppendLine($"{indent}}}");
                }
            }
            else
            {
                // Fallback - use explicit wrapping decode
                sb.AppendLine($"{indent}explicitReader = sequenceReader.ReadSequence({tag});");
                this.EmitFieldDecodeValue(sb, type, propName, fc, indent, false);
                sb.AppendLine($"{indent}explicitReader.ThrowIfNotEmpty();");
            }
        }

        private void EmitFieldDecodeValue(StringBuilder sb, Asn1Type type, string propName, FieldConfig fc, string indent, bool optional, string readerName = "explicitReader")
        {
            string reader = readerName;

            // BackingType override — treat as referenced type for decode
            if (!string.IsNullOrEmpty(fc.BackingType) && !fc.TreatAsEnum
                && !fc.BackingType.EndsWith("[]") && !fc.BackingType.StartsWith("ReadOnlyMemory")
                && fc.BackingType != "string" && fc.BackingType != "Oid" && fc.BackingType != "int"
                && fc.BackingType != "int?" && fc.BackingType != "bool")
            {
                string typeName = fc.BackingType;
                sb.AppendLine($"{indent}{typeName}.Decode<{typeName}>({reader}, out {typeName} tmp{propName});");
                sb.AppendLine($"{indent}decoded.{propName} = tmp{propName};");
                return;
            }

            if (type is Asn1IntegerType)
            {
                string csharpType = (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                    ? fc.EnumType : "int";

                if (optional)
                {
                    sb.AppendLine($"{indent}if ({reader}.TryReadInt32(out {csharpType} tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = tmp{propName};");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}else");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    {reader}.ThrowIfNotEmpty();");
                    sb.AppendLine($"{indent}}}");
                }
                else
                {
                    sb.AppendLine($"{indent}if (!{reader}.TryReadInt32(out {csharpType} tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    {reader}.ThrowIfNotEmpty();");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}");
                    sb.AppendLine($"{indent}decoded.{propName} = tmp{propName};");
                }
            }
            else if (type is Asn1OctetStringType)
            {
                sb.AppendLine($"{indent}if ({reader}.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp{propName}))");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    decoded.{propName} = tmp{propName};");
                sb.AppendLine($"{indent}}}");
                sb.AppendLine($"{indent}else");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    decoded.{propName} = {reader}.ReadOctetString();");
                sb.AppendLine($"{indent}}}");
            }
            else if (type is Asn1BitStringType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    string enumType = fc.EnumType;
                    sb.AppendLine($"{indent}if ({reader}.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = ({enumType})tmp{propName}.AsLong();");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}else");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = ({enumType}){reader}.ReadBitString(out _).AsLong();");
                    sb.AppendLine($"{indent}}}");
                }
                else
                {
                    sb.AppendLine($"{indent}if ({reader}.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmp{propName}))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = tmp{propName};");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}else");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    decoded.{propName} = {reader}.ReadBitString(out _);");
                    sb.AppendLine($"{indent}}}");
                }

                sb.AppendLine();
            }
            else if (type is Asn1BooleanType)
            {
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadBoolean();");
            }
            else if (type is Asn1NullType)
            {
                sb.AppendLine($"{indent}{reader}.ReadNull();");
            }
            else if (type is Asn1ObjectIdentifierType)
            {
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadObjectIdentifier();");
            }
            else if (type is Asn1EnumeratedType)
            {
                string enumType = fc.EnumType ?? fc.BackingType ?? "int";
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadEnumeratedValue<{enumType}>();");
            }
            else if (type is Asn1GeneralizedTimeType)
            {
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadGeneralizedTime();");
            }
            else if (type is Asn1UtcTimeType)
            {
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadUtcTime();");
            }
            else if (type is Asn1StringType strType)
            {
                string utn = GetUniversalTagNumber(strType.Kind);
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadCharacterString(UniversalTagNumber.{utn});");
            }
            else if (type is Asn1SequenceOfType seqOf)
            {
                string elementTypeName = this.GetElementTypeName(seqOf.ElementType, fc);
                sb.AppendLine($"{indent}// Decode SEQUENCE OF for {propName}");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    collectionReader = {reader}.ReadSequence();");
                sb.AppendLine($"{indent}    var tmpList = new List<{elementTypeName}>();");
                sb.AppendLine($"{indent}    {elementTypeName} tmpItem;");
                sb.AppendLine();
                sb.AppendLine($"{indent}    while (collectionReader.HasData)");
                sb.AppendLine($"{indent}    {{");
                this.EmitSequenceOfElementDecode(sb, seqOf.ElementType, fc, "tmpItem", indent + "        ");
                sb.AppendLine($"{indent}        tmpList.Add(tmpItem);");
                sb.AppendLine($"{indent}    }}");
                sb.AppendLine();
                sb.AppendLine($"{indent}    decoded.{propName} = tmpList.ToArray();");
                sb.AppendLine($"{indent}}}");
            }
            else if (type is Asn1ReferencedType refType)
            {
                string typeName = this.ResolveCSharpTypeName(refType.ReferenceName);
                sb.AppendLine($"{indent}{typeName}.Decode<{typeName}>({reader}, out {typeName} tmp{propName});");
                sb.AppendLine($"{indent}decoded.{propName} = tmp{propName};");
            }
            else if (type is Asn1AnyType)
            {
                sb.AppendLine($"{indent}decoded.{propName} = {reader}.ReadEncodedValue();");
            }
        }

        private void EmitSequenceOfElementDecode(StringBuilder sb, Asn1Type elementType, FieldConfig fc, string varName, string indent)
        {
            var resolved = this.ResolveFieldType(elementType);

            // Check resolved primitive types FIRST, before checking if elementType is a reference
            if (resolved is Asn1OctetStringType)
            {
                sb.AppendLine($"{indent}if (collectionReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmp))");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    {varName} = tmp;");
                sb.AppendLine($"{indent}}}");
                sb.AppendLine($"{indent}else");
                sb.AppendLine($"{indent}{{");
                sb.AppendLine($"{indent}    {varName} = collectionReader.ReadOctetString();");
                sb.AppendLine($"{indent}}}");
            }
            else if (resolved is Asn1IntegerType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    sb.AppendLine($"{indent}if (!collectionReader.TryReadInt32<{fc.EnumType}>(out {fc.EnumType} tmp))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    collectionReader.ThrowIfNotEmpty();");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}");
                    sb.AppendLine($"{indent}{varName} = tmp; ");
                }
                else
                {
                    sb.AppendLine($"{indent}if (!collectionReader.TryReadInt32(out int tmp))");
                    sb.AppendLine($"{indent}{{");
                    sb.AppendLine($"{indent}    collectionReader.ThrowIfNotEmpty();");
                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine($"{indent}");
                    sb.AppendLine($"{indent}{varName} = tmp; ");
                }
            }
            else if (resolved is Asn1StringType strType)
            {
                string utn = GetUniversalTagNumber(strType.Kind);
                sb.AppendLine($"{indent}{varName} = collectionReader.ReadCharacterString(UniversalTagNumber.{utn});");
            }
            else if (resolved is Asn1ObjectIdentifierType)
            {
                sb.AppendLine($"{indent}{varName} = collectionReader.ReadObjectIdentifier();");
            }
            else if (fc != null && !string.IsNullOrEmpty(fc.BackingType) && fc.BackingType.EndsWith("[]"))
            {
                // BackingType array override — use the specified element type instead of the ASN.1 type
                string typeName = fc.BackingType.Substring(0, fc.BackingType.Length - 2);
                sb.AppendLine($"{indent}{typeName}.Decode<{typeName}>(collectionReader, out {typeName} tmp);");
                sb.AppendLine($"{indent}{varName} = tmp; ");
            }
            else if (elementType is Asn1ReferencedType refType)
            {
                string typeName = this.ResolveCSharpTypeName(refType.ReferenceName);
                sb.AppendLine($"{indent}{typeName}.Decode<{typeName}>(collectionReader, out {typeName} tmp);");
                sb.AppendLine($"{indent}{varName} = tmp; ");
            }
            else if (elementType is Asn1SequenceType)
            {
                // Inline sequence in SEQUENCE OF - decode as self type
                sb.AppendLine($"{indent}// inline sequence element decode");
            }
        }

        #endregion

        #region Helpers

        private TypeConfig GetTypeConfig(string name)
        {
            if (this.config.Types.TryGetValue(name, out var tc))
            {
                return tc;
            }

            return new TypeConfig { CSharpName = ToPascalCase(name) };
        }

        private FieldConfig GetFieldConfig(TypeConfig tc, string fieldName)
        {
            if (tc.Fields.TryGetValue(fieldName, out var fc))
            {
                return fc;
            }

            return new FieldConfig();
        }

        private string ResolveCSharpTypeName(string asnName)
        {
            if (this.config.Types.TryGetValue(asnName, out var tc) && tc.CSharpName != null)
            {
                return tc.CSharpName;
            }

            return ToPascalCase(asnName);
        }

        private string GetChoiceFieldCSharpType(Asn1Field field, FieldConfig fc)
        {
            // CHOICE fields are always nullable (only one is set at a time)
            var baseType = this.GetCSharpType(field, fc);

            // Value types need ? suffix; reference types are already nullable
            if (baseType == "int" || baseType == "bool" || baseType == "DateTimeOffset"
                || baseType == "ReadOnlyMemory<byte>")
            {
                return baseType + "?";
            }

            return baseType;
        }

        private string GetCSharpType(Asn1Field field, FieldConfig fc)
        {
            // BackingType override takes precedence
            if (!string.IsNullOrEmpty(fc.BackingType))
            {
                return fc.BackingType;
            }

            var type = this.UnwrapTaggedType(field.Type);
            var resolved = this.ResolveFieldType(type);
            bool optional = field.Optional;

            return this.GetCSharpTypeForAsn1Type(resolved, fc, optional);
        }

        private string GetCSharpTypeForAsn1Type(Asn1Type type, FieldConfig fc, bool optional)
        {
            if (type is Asn1IntegerType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    return fc.EnumType;
                }

                return optional ? "int?" : "int";
            }

            if (type is Asn1BooleanType)
            {
                return optional ? "bool?" : "bool";
            }

            if (type is Asn1OctetStringType)
            {
                return optional ? "ReadOnlyMemory<byte>?" : "ReadOnlyMemory<byte>";
            }

            if (type is Asn1BitStringType)
            {
                if (fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    return fc.EnumType;
                }

                return optional ? "ReadOnlyMemory<byte>?" : "ReadOnlyMemory<byte>";
            }

            if (type is Asn1NullType)
            {
                return "ReadOnlyMemory<byte>?";
            }

            if (type is Asn1ObjectIdentifierType)
            {
                return "Oid";
            }

            if (type is Asn1EnumeratedType)
            {
                return fc.EnumType ?? fc.BackingType ?? "int";
            }

            if (type is Asn1GeneralizedTimeType || type is Asn1UtcTimeType)
            {
                return optional ? "DateTimeOffset?" : "DateTimeOffset";
            }

            if (type is Asn1StringType)
            {
                return "string";
            }

            if (type is Asn1SequenceOfType seqOf)
            {
                string elemType = this.GetElementTypeName(seqOf.ElementType, fc);
                return $"{elemType}[]";
            }

            if (type is Asn1SetOfType setOf)
            {
                string elemType = this.GetElementTypeName(setOf.ElementType, fc);
                return $"{elemType}[]";
            }

            if (type is Asn1ReferencedType refType)
            {
                return this.ResolveCSharpTypeName(refType.ReferenceName);
            }

            if (type is Asn1AnyType)
            {
                return optional ? "ReadOnlyMemory<byte>?" : "ReadOnlyMemory<byte>";
            }

            return "object";
        }

        private string GetElementTypeName(Asn1Type elementType, FieldConfig fc = null)
        {
            // If BackingType is an array like "KrbAuthorizationData[]", extract the element type
            if (fc != null && !string.IsNullOrEmpty(fc.BackingType) && fc.BackingType.EndsWith("[]"))
            {
                return fc.BackingType.Substring(0, fc.BackingType.Length - 2);
            }

            // Resolve through aliases first
            var resolved = this.ResolveFieldType(elementType);

            if (resolved is Asn1OctetStringType)
            {
                return "ReadOnlyMemory<byte>";
            }

            if (resolved is Asn1IntegerType)
            {
                if (fc != null && fc.TreatAsEnum && !string.IsNullOrEmpty(fc.EnumType))
                {
                    return fc.EnumType;
                }

                return "int";
            }

            if (resolved is Asn1StringType)
            {
                return "string";
            }

            if (resolved is Asn1ObjectIdentifierType)
            {
                return "Oid";
            }

            if (elementType is Asn1ReferencedType refType)
            {
                return this.ResolveCSharpTypeName(refType.ReferenceName);
            }

            return "object";
        }

        private string GetReferencedTypeName(Asn1Field field)
        {
            var inner = this.UnwrapTaggedType(field.Type);

            if (inner is Asn1ReferencedType refType)
            {
                return this.ResolveCSharpTypeName(refType.ReferenceName);
            }

            return ToPascalCase(field.Name);
        }

        private Asn1Type UnwrapTaggedType(Asn1Type type)
        {
            while (type is Asn1TaggedType tagged)
            {
                type = tagged.InnerType;
            }

            return type;
        }

        private int GetTagNumber(Asn1Field field)
        {
            if (field.Type is Asn1TaggedType tagged)
            {
                return tagged.TagNumber;
            }

            return 0;
        }

        private bool IsSequenceOfField(Asn1Field field)
        {
            var inner = this.UnwrapTaggedType(field.Type);
            var resolved = this.ResolveFieldType(inner);
            return resolved is Asn1SequenceOfType || inner is Asn1SequenceOfType;
        }

        private bool IsSetOfField(Asn1Field field)
        {
            var inner = this.UnwrapTaggedType(field.Type);
            var resolved = this.ResolveFieldType(inner);
            return resolved is Asn1SetOfType || inner is Asn1SetOfType;
        }

        private bool IsPrimitiveType(Asn1Type type)
        {
            return type is Asn1OctetStringType ||
                   type is Asn1IntegerType ||
                   type is Asn1BitStringType ||
                   type is Asn1BooleanType ||
                   type is Asn1NullType ||
                   type is Asn1ObjectIdentifierType ||
                   type is Asn1GeneralizedTimeType ||
                   type is Asn1UtcTimeType ||
                   type is Asn1StringType;
        }

        private bool NeedsCollections(Asn1Type type)
        {
            if (type is Asn1SequenceType seq)
            {
                return seq.Fields.Any(f =>
                {
                    var inner = this.UnwrapTaggedType(f.Type);
                    var resolved = this.ResolveFieldType(inner);
                    return resolved is Asn1SequenceOfType || inner is Asn1SequenceOfType ||
                           resolved is Asn1SetOfType || inner is Asn1SetOfType;
                });
            }

            return false;
        }

        private static string GetUniversalTagNumber(Asn1StringKind kind)
        {
            return kind switch
            {
                Asn1StringKind.UTF8String => "UTF8String",
                Asn1StringKind.PrintableString => "PrintableString",
                Asn1StringKind.IA5String => "IA5String",
                Asn1StringKind.VisibleString => "VisibleString",
                Asn1StringKind.GeneralString => "GeneralString",
                Asn1StringKind.BMPString => "BMPString",
                Asn1StringKind.T61String => "T61String",
                _ => "UTF8String",
            };
        }

        public static string ToPascalCase(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return name;
            }

            var parts = name.Split('-', '_');
            var sb = new StringBuilder();

            foreach (var part in parts)
            {
                if (part.Length > 0)
                {
                    sb.Append(char.ToUpperInvariant(part[0]));
                    sb.Append(part.Substring(1));
                }
            }

            return sb.ToString();
        }

        #endregion
    }
}
