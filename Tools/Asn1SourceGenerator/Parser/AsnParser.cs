// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using Kerberos.NET.Asn1SourceGenerator.Model;

namespace Kerberos.NET.Asn1SourceGenerator.Parser
{
    /// <summary>
    /// Recursive descent parser for ASN.1 schema notation.
    /// Consumes tokens from <see cref="AsnTokenizer"/> and produces an <see cref="AsnSchema"/>.
    /// </summary>
    public class AsnParser
    {
        private readonly AsnTokenizer _tokenizer;
        private readonly List<string> _diagnostics = new List<string>();
        private AsnTagDefault _moduleTagDefault = AsnTagDefault.Explicit;

        private AsnParser(AsnTokenizer tokenizer)
        {
            _tokenizer = tokenizer;
        }

        /// <summary>
        /// Parse the given ASN.1 source text into an <see cref="AsnSchema"/>.
        /// </summary>
        public static AsnSchema Parse(string input)
        {
            return Parse(input, out _);
        }

        /// <summary>
        /// Parse the given ASN.1 source text into an <see cref="AsnSchema"/>,
        /// returning any diagnostics encountered during tolerant parsing.
        /// </summary>
        public static AsnSchema Parse(string input, out IReadOnlyList<string> diagnostics)
        {
            var tokenizer = new AsnTokenizer(input);
            var parser = new AsnParser(tokenizer);
            var schema = parser.ParseSchema();
            diagnostics = parser.Diagnostics;
            return schema;
        }

        /// <summary>
        /// Diagnostics emitted during tolerant parsing (skipped constructs, etc.).
        /// </summary>
        public IReadOnlyList<string> Diagnostics => _diagnostics;

        // ─── Schema / Module ─────────────────────────────────────────

        private AsnSchema ParseSchema()
        {
            var schema = new AsnSchema();

            while (Peek().Kind != AsnTokenKind.EndOfFile)
            {
                try
                {
                    var module = ParseModule();
                    schema.Modules.Add(module);
                }
                catch (AsnParseException ex)
                {
                    _diagnostics.Add(ex.Message);
                    SkipToNextModule();
                }
            }

            return schema;
        }

        private AsnModule ParseModule()
        {
            var module = new AsnModule();

            // Collect any leading annotations for the module
            var leadingAnnotations = CollectAnnotations();

            // Module name — may be hyphenated like "KerberosV5-PK-INIT-SPEC"
            module.Name = ExpectIdentifier("module name");

            // Optional OID arcs: { iso ... }
            if (Peek().Kind == AsnTokenKind.LeftBrace)
            {
                SkipBraceBlock();
            }

            ExpectKeyword("DEFINITIONS");

            // Optional tag default: EXPLICIT TAGS | IMPLICIT TAGS | AUTOMATIC TAGS
            if (PeekIsKeyword("EXPLICIT"))
            {
                Next();
                module.TagDefault = AsnTagDefault.Explicit;
                ExpectKeyword("TAGS");
            }
            else if (PeekIsKeyword("IMPLICIT"))
            {
                Next();
                module.TagDefault = AsnTagDefault.Implicit;
                ExpectKeyword("TAGS");
            }
            else if (PeekIsKeyword("AUTOMATIC"))
            {
                Next();
                module.TagDefault = AsnTagDefault.Automatic;
                ExpectKeyword("TAGS");
            }

            _moduleTagDefault = module.TagDefault;

            Expect(AsnTokenKind.Assignment); // ::=
            ExpectKeyword("BEGIN");

            // Apply leading annotations to module
            ApplyModuleAnnotations(module.Annotations, leadingAnnotations);

            // Collect any annotations right after BEGIN (module-level)
            var postBeginAnnotations = CollectAnnotations();
            ApplyModuleAnnotations(module.Annotations, postBeginAnnotations);

            // Parse module body: imports, type assignments, value assignments
            ParseModuleBody(module);

            ExpectKeyword("END");

            return module;
        }

        private void ParseModuleBody(AsnModule module)
        {
            // IMPORTS section
            if (PeekIsKeyword("IMPORTS"))
            {
                ParseImports(module);
            }

            // Type and value assignments until END
            while (Peek().Kind != AsnTokenKind.EndOfFile && !PeekIsKeyword("END"))
            {
                try
                {
                    // Collect annotations before an assignment
                    var annotations = CollectAnnotations();

                    if (Peek().Kind == AsnTokenKind.EndOfFile || PeekIsKeyword("END"))
                    {
                        break;
                    }

                    ParseAssignment(module, annotations);
                }
                catch (AsnParseException ex)
                {
                    _diagnostics.Add(ex.Message);
                    SkipToNextAssignment();
                }
            }
        }

        // ─── IMPORTS ─────────────────────────────────────────────────

        private void ParseImports(AsnModule module)
        {
            ExpectKeyword("IMPORTS");

            while (Peek().Kind != AsnTokenKind.Semicolon && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                var import = new AsnImport();

                // Read symbols until FROM
                while (!PeekIsKeyword("FROM") && Peek().Kind != AsnTokenKind.EndOfFile)
                {
                    import.Symbols.Add(ExpectIdentifier("import symbol"));

                    if (Peek().Kind == AsnTokenKind.Comma)
                    {
                        Next();
                    }
                }

                ExpectKeyword("FROM");
                import.FromModule = ExpectIdentifier("module name");

                // Skip optional OID arcs
                if (Peek().Kind == AsnTokenKind.LeftBrace)
                {
                    SkipBraceBlock();
                }

                module.Imports.Add(import);
            }

            Expect(AsnTokenKind.Semicolon);
        }

        // ─── Assignments ─────────────────────────────────────────────

        private void ParseAssignment(AsnModule module, List<ParsedAnnotation> annotations)
        {
            var name = ExpectIdentifier("assignment name");

            // Distinguish value assignment from type assignment.
            // Value assignments have a type keyword before ::=
            // Type assignments have ::= immediately after the name, or a tag [APPLICATION n] before ::=
            // Heuristic: if next token is a well-known primitive type keyword followed by ::=,
            // it's a value assignment. Type names start uppercase; field/value names start lowercase.
            // However, the ASN.1 convention is: uppercase = type, lowercase = value.

            if (IsValueAssignment(name))
            {
                ParseValueAssignment(module, name);
            }
            else
            {
                ParseTypeAssignment(module, name, annotations);
            }
        }

        private bool IsValueAssignment(string name)
        {
            // Value names in ASN.1 start with a lowercase letter
            if (name.Length > 0 && char.IsLower(name[0]))
            {
                return true;
            }

            return false;
        }

        private void ParseValueAssignment(AsnModule module, string name)
        {
            var va = new AsnValueAssignment { Name = name };

            // Consume the type name (could be multi-word like OBJECT IDENTIFIER)
            var typeParts = new List<string>();

            while (Peek().Kind == AsnTokenKind.Identifier && Peek().Kind != AsnTokenKind.Assignment)
            {
                typeParts.Add(Next().Value);

                if (Peek().Kind == AsnTokenKind.Assignment)
                {
                    break;
                }
            }

            va.TypeName = string.Join(" ", typeParts);
            Expect(AsnTokenKind.Assignment);

            // Consume the value — could be a number, braced OID, or identifier
            va.Value = ParseValueLiteral();

            module.ValueAssignments.Add(va);
        }

        private string ParseValueLiteral()
        {
            var token = Peek();

            if (token.Kind == AsnTokenKind.Number)
            {
                return Next().Value;
            }

            if (token.Kind == AsnTokenKind.LeftBrace)
            {
                return ConsumeBraceContent();
            }

            if (token.Kind == AsnTokenKind.Identifier)
            {
                return Next().Value;
            }

            // Fallback: just consume whatever is there
            return Next().Value;
        }

        private void ParseTypeAssignment(AsnModule module, string name, List<ParsedAnnotation> annotations)
        {
            Expect(AsnTokenKind.Assignment);

            var type = ParseType();

            var ta = new AsnTypeAssignment
            {
                Name = name,
                Type = type,
            };

            ApplyTypeAnnotations(ta.Annotations, annotations);

            module.TypeAssignments.Add(ta);
        }

        // ─── Type Parsing ────────────────────────────────────────────

        private AsnType ParseType()
        {
            // Check for tag: [n] or [APPLICATION n] etc.
            AsnTag? tag = null;

            if (Peek().Kind == AsnTokenKind.LeftBracket)
            {
                tag = ParseTag();
            }

            var type = ParseTypeBody(tag);
            type.Tag = tag;

            return type;
        }

        private AsnType ParseTypeBody(AsnTag? tag)
        {
            var token = Peek();

            if (token.Kind == AsnTokenKind.Identifier)
            {
                string value = token.Value;

                switch (value)
                {
                    case "SEQUENCE":
                        return ParseSequenceOrSequenceOf();

                    case "SET":
                        return ParseSetOf();

                    case "CHOICE":
                        return ParseChoice();

                    case "INTEGER":
                        return ParseInteger();

                    case "ENUMERATED":
                        return ParseEnumerated();

                    case "BIT":
                        return ParseBitString();

                    case "OCTET":
                        return ParseOctetString();

                    case "BOOLEAN":
                        Next();
                        return new AsnPrimitiveType { Kind = AsnPrimitiveKind.Boolean };

                    case "NULL":
                        Next();
                        return new AsnPrimitiveType { Kind = AsnPrimitiveKind.Null };

                    case "OBJECT":
                        return ParseObjectIdentifier();

                    case "ANY":
                        return ParseAny();

                    case "GeneralizedTime":
                        Next();
                        return new AsnPrimitiveType { Kind = AsnPrimitiveKind.GeneralizedTime };

                    case "UTCTime":
                        Next();
                        return new AsnPrimitiveType { Kind = AsnPrimitiveKind.UtcTime };

                    case "GeneralString":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.GeneralString);

                    case "UTF8String":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.UTF8String);

                    case "PrintableString":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.PrintableString);

                    case "IA5String":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.IA5String);

                    case "VisibleString":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.VisibleString);

                    case "T61String":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.T61String);

                    case "BMPString":
                        Next();
                        return ParseStringConstraint(AsnPrimitiveKind.BMPString);

                    default:
                        // Referenced type or tagged type alias
                        return ParseReferencedOrAlias(tag);
                }
            }

            throw new AsnParseException(
                $"Expected type but found {token.Kind} '{token.Value}'",
                token.Line, token.Column);
        }

        private AsnType ParseReferencedOrAlias(AsnTag? tag)
        {
            string referencedName = Next().Value;

            // Optional constraint on the referenced type
            TryParseConstraintParens();

            if (tag != null && tag.Class == AsnTagClass.Application)
            {
                // [APPLICATION n] TypeRef → AsnTaggedTypeAlias (inheritance pattern)
                return new AsnTaggedTypeAlias { ReferencedName = referencedName };
            }

            // Context tags [n] on fields or plain references — always AsnReferencedType
            return new AsnReferencedType { ReferencedName = referencedName };
        }

        // ─── SEQUENCE / SEQUENCE OF ─────────────────────────────────

        private AsnType ParseSequenceOrSequenceOf()
        {
            ExpectKeyword("SEQUENCE");

            // SIZE constraint before OF: SEQUENCE SIZE (1..MAX) OF Type
            AsnSizeConstraint? sizeConstraint = null;

            if (PeekIsKeyword("SIZE"))
            {
                sizeConstraint = ParseSizeKeywordConstraint();
            }

            if (PeekIsKeyword("OF"))
            {
                Next(); // consume OF
                var elementType = ParseType();

                return new AsnCollectionType
                {
                    IsSetOf = false,
                    ElementType = elementType,
                    SizeConstraint = sizeConstraint,
                };
            }

            // SIZE constraint in parens: SEQUENCE (SIZE (1..MAX)) OF Type
            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                sizeConstraint = TryParseSizeConstraintParen();

                if (PeekIsKeyword("OF"))
                {
                    Next(); // consume OF
                    var elementType = ParseType();

                    return new AsnCollectionType
                    {
                        IsSetOf = false,
                        ElementType = elementType,
                        SizeConstraint = sizeConstraint,
                    };
                }
            }

            // SEQUENCE { ... } — structured type
            return ParseSequenceBody();
        }

        private AsnSequenceType ParseSequenceBody()
        {
            Expect(AsnTokenKind.LeftBrace);

            var seq = new AsnSequenceType();
            ParseFieldList(seq.Fields, out bool extensible);
            seq.Extensible = extensible;

            Expect(AsnTokenKind.RightBrace);
            return seq;
        }

        // ─── SET OF ─────────────────────────────────────────────────

        private AsnType ParseSetOf()
        {
            ExpectKeyword("SET");

            AsnSizeConstraint? sizeConstraint = null;

            if (PeekIsKeyword("SIZE"))
            {
                sizeConstraint = ParseSizeKeywordConstraint();
            }

            if (PeekIsKeyword("OF"))
            {
                Next(); // consume OF
                var elementType = ParseType();

                return new AsnCollectionType
                {
                    IsSetOf = true,
                    ElementType = elementType,
                    SizeConstraint = sizeConstraint,
                };
            }

            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                sizeConstraint = TryParseSizeConstraintParen();

                if (PeekIsKeyword("OF"))
                {
                    Next();
                    var elementType = ParseType();

                    return new AsnCollectionType
                    {
                        IsSetOf = true,
                        ElementType = elementType,
                        SizeConstraint = sizeConstraint,
                    };
                }
            }

            // SET { ... } — not commonly used but handle like SEQUENCE
            Expect(AsnTokenKind.LeftBrace);
            var seq = new AsnSequenceType();
            ParseFieldList(seq.Fields, out bool extensible);
            seq.Extensible = extensible;
            Expect(AsnTokenKind.RightBrace);
            return seq;
        }

        // ─── CHOICE ─────────────────────────────────────────────────

        private AsnType ParseChoice()
        {
            ExpectKeyword("CHOICE");
            Expect(AsnTokenKind.LeftBrace);

            var choice = new AsnChoiceType();
            ParseFieldList(choice.Alternatives, out bool extensible);
            choice.Extensible = extensible;

            Expect(AsnTokenKind.RightBrace);
            return choice;
        }

        // ─── Field Lists (SEQUENCE / CHOICE bodies) ─────────────────

        private void ParseFieldList(List<AsnField> fields, out bool extensible)
        {
            extensible = false;

            while (Peek().Kind != AsnTokenKind.RightBrace && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                // Collect annotations before a field
                var annotations = CollectAnnotations();

                if (Peek().Kind == AsnTokenKind.RightBrace)
                {
                    break;
                }

                // Extensibility marker: ...
                if (Peek().Kind == AsnTokenKind.Ellipsis)
                {
                    Next();
                    extensible = true;

                    if (Peek().Kind == AsnTokenKind.Comma)
                    {
                        Next();
                    }

                    continue;
                }

                // COMPONENTS OF TypeName — skip
                if (PeekIsKeyword("COMPONENTS"))
                {
                    Next(); // COMPONENTS
                    ExpectKeyword("OF");
                    ExpectIdentifier("referenced type"); // type name
                    if (Peek().Kind == AsnTokenKind.Comma) Next();
                    continue;
                }

                var field = ParseField(annotations);
                fields.Add(field);

                // Annotations and comma can appear in either order:
                // Case 1: field TYPE -- @cs-name: Foo \n -- comment --,
                // Case 2: field TYPE, -- @cs-name: Foo
                // Collect annotations, consume comma, collect more annotations.
                var trailingAnnotations = CollectAnnotations();

                if (Peek().Kind == AsnTokenKind.Comma)
                {
                    Next();
                }

                var moreAnnotations = CollectAnnotations();
                foreach (var a in moreAnnotations)
                    trailingAnnotations.Add(a);

                ApplyFieldAnnotations(field.Annotations, trailingAnnotations);
            }
        }

        private AsnField ParseField(List<ParsedAnnotation> annotations)
        {
            var field = new AsnField();

            field.Name = ExpectIdentifier("field name");
            field.Type = ParseType();

            // OPTIONAL or DEFAULT
            if (PeekIsKeyword("OPTIONAL"))
            {
                Next();
                field.Optional = true;
            }
            else if (PeekIsKeyword("DEFAULT"))
            {
                Next();
                field.HasDefault = true;
                field.DefaultValue = ParseDefaultValue();
            }

            ApplyFieldAnnotations(field.Annotations, annotations);

            return field;
        }

        private string ParseDefaultValue()
        {
            var token = Peek();

            if (token.Kind == AsnTokenKind.Number)
            {
                return Next().Value;
            }

            if (token.Kind == AsnTokenKind.Identifier)
            {
                return Next().Value;
            }

            if (token.Kind == AsnTokenKind.LeftBrace)
            {
                return ConsumeBraceContent();
            }

            // Fallback: return empty string rather than failing
            return "";
        }

        // ─── Primitive Types ─────────────────────────────────────────

        private AsnPrimitiveType ParseInteger()
        {
            ExpectKeyword("INTEGER");

            var pt = new AsnPrimitiveType { Kind = AsnPrimitiveKind.Integer };

            // Named values: INTEGER { val1(0), val2(1) }
            if (Peek().Kind == AsnTokenKind.LeftBrace)
            {
                pt.NamedValues = ParseNamedValues();
            }

            // Constraint: INTEGER (0..255)
            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                pt.Constraint = ParseValueConstraint();
            }

            return pt;
        }

        private AsnPrimitiveType ParseEnumerated()
        {
            ExpectKeyword("ENUMERATED");

            var pt = new AsnPrimitiveType { Kind = AsnPrimitiveKind.Enumerated };

            if (Peek().Kind == AsnTokenKind.LeftBrace)
            {
                pt.NamedValues = ParseNamedValues();
            }

            return pt;
        }

        private AsnPrimitiveType ParseBitString()
        {
            ExpectKeyword("BIT");
            ExpectKeyword("STRING");

            var pt = new AsnPrimitiveType { Kind = AsnPrimitiveKind.BitString };

            // Named bits: BIT STRING { flag1(0), flag2(1) }
            if (Peek().Kind == AsnTokenKind.LeftBrace)
            {
                pt.NamedValues = ParseNamedValues();
            }

            // Constraint: (SIZE (32))
            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                pt.Constraint = TryParseSizeConstraintParen();
            }

            return pt;
        }

        private AsnPrimitiveType ParseOctetString()
        {
            ExpectKeyword("OCTET");
            ExpectKeyword("STRING");

            var pt = new AsnPrimitiveType { Kind = AsnPrimitiveKind.OctetString };

            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                pt.Constraint = TryParseSizeConstraintParen();
            }

            return pt;
        }

        private AsnType ParseObjectIdentifier()
        {
            ExpectKeyword("OBJECT");
            ExpectKeyword("IDENTIFIER");

            return new AsnPrimitiveType { Kind = AsnPrimitiveKind.ObjectIdentifier };
        }

        private AsnPrimitiveType ParseStringConstraint(AsnPrimitiveKind kind)
        {
            var pt = new AsnPrimitiveType { Kind = kind };

            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                pt.Constraint = TryParseSizeConstraintParen();
            }

            return pt;
        }

        // ─── ANY ─────────────────────────────────────────────────────

        private AsnAnyType ParseAny()
        {
            ExpectKeyword("ANY");

            var any = new AsnAnyType();

            if (PeekIsKeyword("DEFINED"))
            {
                Next(); // DEFINED
                ExpectKeyword("BY");
                any.DefinedBy = ExpectIdentifier("field name");
            }

            return any;
        }

        // ─── Tags ───────────────────────────────────────────────────

        private AsnTag ParseTag()
        {
            Expect(AsnTokenKind.LeftBracket);

            var tag = new AsnTag();

            // Check for tag class keyword
            if (PeekIsKeyword("APPLICATION"))
            {
                Next();
                tag.Class = AsnTagClass.Application;
            }
            else if (PeekIsKeyword("UNIVERSAL"))
            {
                Next();
                tag.Class = AsnTagClass.Universal;
            }
            else if (PeekIsKeyword("PRIVATE"))
            {
                Next();
                tag.Class = AsnTagClass.Private;
            }
            else
            {
                tag.Class = AsnTagClass.ContextSpecific;
            }

            // Tag number
            var numToken = Expect(AsnTokenKind.Number);
            tag.Number = int.Parse(numToken.Value);

            Expect(AsnTokenKind.RightBracket);

            // Tag mode: EXPLICIT or IMPLICIT after the bracket
            if (PeekIsKeyword("EXPLICIT"))
            {
                Next();
                tag.Mode = AsnTagMode.Explicit;
            }
            else if (PeekIsKeyword("IMPLICIT"))
            {
                Next();
                tag.Mode = AsnTagMode.Implicit;
            }
            else
            {
                // Use module default
                tag.Mode = _moduleTagDefault switch
                {
                    AsnTagDefault.Explicit => AsnTagMode.Explicit,
                    AsnTagDefault.Implicit => AsnTagMode.Implicit,
                    AsnTagDefault.Automatic => AsnTagMode.Implicit,
                    _ => AsnTagMode.Explicit,
                };
            }

            return tag;
        }

        // ─── Named Values / Named Bits ──────────────────────────────

        private List<AsnNamedValue> ParseNamedValues()
        {
            Expect(AsnTokenKind.LeftBrace);

            var values = new List<AsnNamedValue>();

            while (Peek().Kind != AsnTokenKind.RightBrace && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                // Extensibility marker in named values
                if (Peek().Kind == AsnTokenKind.Ellipsis)
                {
                    Next();
                    if (Peek().Kind == AsnTokenKind.Comma) Next();
                    continue;
                }

                var nv = new AsnNamedValue();
                nv.Name = ExpectIdentifier("named value");
                Expect(AsnTokenKind.LeftParen);
                var numToken = Expect(AsnTokenKind.Number);
                nv.Value = int.Parse(numToken.Value);
                Expect(AsnTokenKind.RightParen);

                values.Add(nv);

                if (Peek().Kind == AsnTokenKind.Comma)
                {
                    Next();
                }
            }

            Expect(AsnTokenKind.RightBrace);
            return values;
        }

        // ─── Constraints ─────────────────────────────────────────────

        private AsnValueConstraint ParseValueConstraint()
        {
            Expect(AsnTokenKind.LeftParen);

            var constraint = new AsnValueConstraint();

            // Single value: (5)
            // Range: (0..255)
            // Range with MAX: (0..MAX)
            // Union: (10 | 12)
            var first = ParseConstraintValue();
            constraint.MinValue = first;

            if (Peek().Kind == AsnTokenKind.Dot)
            {
                // Consume ".."
                Next(); // first dot
                Next(); // second dot
                constraint.MaxValue = ParseConstraintMaxValue(out bool maxIsMax);
                constraint.MaxIsMax = maxIsMax;
            }
            else
            {
                // Single value constraint — min == max
                constraint.MaxValue = first;
            }

            // Skip union alternatives: | value [| value ...]
            while (Peek().Kind == AsnTokenKind.Pipe)
            {
                Next(); // consume |
                ParseConstraintValue(); // consume the alternative value
            }

            Expect(AsnTokenKind.RightParen);
            return constraint;
        }

        private AsnSizeConstraint? TryParseSizeConstraintParen()
        {
            if (Peek().Kind != AsnTokenKind.LeftParen)
            {
                return null;
            }

            Expect(AsnTokenKind.LeftParen);

            AsnSizeConstraint? result = null;

            if (PeekIsKeyword("SIZE"))
            {
                result = ParseSizeKeywordConstraint();
            }
            else
            {
                // Could be a value constraint or other — skip contents
                SkipParenContent();
            }

            Expect(AsnTokenKind.RightParen);
            return result;
        }

        private AsnSizeConstraint ParseSizeKeywordConstraint()
        {
            ExpectKeyword("SIZE");
            Expect(AsnTokenKind.LeftParen);

            var constraint = new AsnSizeConstraint();

            var first = ParseConstraintValue();
            constraint.MinSize = first;

            if (Peek().Kind == AsnTokenKind.Dot)
            {
                Next(); // first dot
                Next(); // second dot
                constraint.MaxSize = ParseConstraintMaxValue(out bool maxIsMax);
                constraint.MaxIsMax = maxIsMax;
            }
            else
            {
                constraint.MaxSize = first;
            }

            Expect(AsnTokenKind.RightParen);
            return constraint;
        }

        private long? ParseConstraintValue()
        {
            var token = Peek();

            if (token.Kind == AsnTokenKind.Number)
            {
                Next();
                return long.Parse(token.Value);
            }

            if (token.Kind == AsnTokenKind.Identifier && token.Value == "MIN")
            {
                Next();
                return null;
            }

            return null;
        }

        private long? ParseConstraintMaxValue(out bool maxIsMax)
        {
            maxIsMax = false;
            var token = Peek();

            if (token.Kind == AsnTokenKind.Number)
            {
                Next();
                return long.Parse(token.Value);
            }

            if (token.Kind == AsnTokenKind.Identifier && token.Value == "MAX")
            {
                Next();
                maxIsMax = true;
                return null;
            }

            return null;
        }

        private void TryParseConstraintParens()
        {
            if (Peek().Kind == AsnTokenKind.LeftParen)
            {
                Expect(AsnTokenKind.LeftParen);
                SkipParenContent();
                Expect(AsnTokenKind.RightParen);
            }
        }

        // ─── Annotations ─────────────────────────────────────────────

        private struct ParsedAnnotation
        {
            public string Key;
            public string Value;
        }

        private List<ParsedAnnotation> CollectAnnotations()
        {
            var annotations = new List<ParsedAnnotation>();

            while (Peek().Kind == AsnTokenKind.AnnotationComment)
            {
                var token = Next();
                // Value may contain multiple annotations like "@cs-name: Foo @cs-type: int"
                var parsed = ParseAllAnnotations(token.Value);
                annotations.AddRange(parsed);
            }

            return annotations;
        }

        private ParsedAnnotation? ParseAnnotationValue(string text)
        {
            // Format: "@cs-key: value" (single annotation)
            if (!text.StartsWith("@cs-"))
            {
                return null;
            }

            int colonIndex = text.IndexOf(':');

            if (colonIndex < 0)
            {
                return null;
            }

            string key = text.Substring(4, colonIndex - 4).Trim(); // strip "@cs-"
            string rawValue = text.Substring(colonIndex + 1).Trim();

            // If value contains another @cs- annotation, truncate at that point
            int nextAnnotation = rawValue.IndexOf("@cs-");
            string value = nextAnnotation >= 0
                ? rawValue.Substring(0, nextAnnotation).Trim()
                : rawValue;

            return new ParsedAnnotation { Key = key, Value = value };
        }

        private List<ParsedAnnotation> ParseAllAnnotations(string text)
        {
            var results = new List<ParsedAnnotation>();
            int pos = 0;

            while (pos < text.Length)
            {
                int start = text.IndexOf("@cs-", pos);
                if (start < 0)
                    break;

                var parsed = ParseAnnotationValue(text.Substring(start));
                if (parsed.HasValue)
                {
                    results.Add(parsed.Value);
                }

                // Move past this @cs- to find the next
                int nextAt = text.IndexOf("@cs-", start + 4);
                pos = nextAt >= 0 ? nextAt : text.Length;
            }

            return results;
        }

        private static void ApplyModuleAnnotations(AsnModuleAnnotations target, List<ParsedAnnotation> annotations)
        {
            foreach (var a in annotations)
            {
                switch (a.Key)
                {
                    case "namespace":
                        target.Namespace = a.Value;
                        break;
                    case "prefix":
                        target.ClassPrefix = a.Value;
                        break;
                }
            }
        }

        private static void ApplyTypeAnnotations(AsnTypeAnnotations target, List<ParsedAnnotation> annotations)
        {
            foreach (var a in annotations)
            {
                switch (a.Key)
                {
                    case "class":
                        target.ClassName = a.Value;
                        break;
                    case "namespace":
                        target.Namespace = a.Value;
                        break;
                    case "name":
                        target.PropertyName = a.Value;
                        break;
                    case "enum":
                        target.EnumType = a.Value;
                        break;
                }
            }
        }

        private static void ApplyFieldAnnotations(AsnFieldAnnotations target, List<ParsedAnnotation> annotations)
        {
            foreach (var a in annotations)
            {
                switch (a.Key)
                {
                    case "name":
                        target.PropertyName = a.Value;
                        break;
                    case "type":
                        target.BackingType = a.Value;
                        break;
                    case "enum":
                        target.EnumType = a.Value;
                        break;
                    case "flags-enum":
                        target.FlagsEnumType = a.Value;
                        break;
                    case "default-der":
                        target.DefaultDerInit = a.Value;
                        break;
                }
            }
        }

        // ─── Token Helpers ───────────────────────────────────────────

        private AsnToken Next() => _tokenizer.NextToken();

        private AsnToken Peek() => _tokenizer.PeekToken();

        private AsnToken Expect(AsnTokenKind kind)
        {
            var token = Next();

            if (token.Kind != kind)
            {
                throw new AsnParseException(
                    $"Expected {kind} but found {token.Kind} '{token.Value}'",
                    token.Line, token.Column);
            }

            return token;
        }

        private string ExpectIdentifier(string context)
        {
            var token = Next();

            if (token.Kind != AsnTokenKind.Identifier)
            {
                throw new AsnParseException(
                    $"Expected {context} (identifier) but found {token.Kind} '{token.Value}'",
                    token.Line, token.Column);
            }

            return token.Value;
        }

        private void ExpectKeyword(string keyword)
        {
            var token = Next();

            if (token.Kind != AsnTokenKind.Identifier || token.Value != keyword)
            {
                throw new AsnParseException(
                    $"Expected keyword '{keyword}' but found {token.Kind} '{token.Value}'",
                    token.Line, token.Column);
            }
        }

        private bool PeekIsKeyword(string keyword)
        {
            var token = Peek();
            return token.Kind == AsnTokenKind.Identifier && token.Value == keyword;
        }

        // ─── Skip / Recovery Helpers ─────────────────────────────────

        private void SkipBraceBlock()
        {
            Expect(AsnTokenKind.LeftBrace);
            int depth = 1;

            while (depth > 0 && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                var token = Next();

                if (token.Kind == AsnTokenKind.LeftBrace) depth++;
                else if (token.Kind == AsnTokenKind.RightBrace) depth--;
            }
        }

        private string ConsumeBraceContent()
        {
            Expect(AsnTokenKind.LeftBrace);
            int depth = 1;
            var parts = new List<string>();

            while (depth > 0 && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                var token = Next();

                if (token.Kind == AsnTokenKind.LeftBrace) depth++;
                else if (token.Kind == AsnTokenKind.RightBrace) depth--;

                if (depth > 0)
                {
                    parts.Add(token.Value);
                }
            }

            return "{ " + string.Join(" ", parts) + " }";
        }

        private void SkipParenContent()
        {
            int depth = 1;

            while (depth > 0 && Peek().Kind != AsnTokenKind.EndOfFile)
            {
                var token = Peek();

                if (token.Kind == AsnTokenKind.LeftParen)
                {
                    Next();
                    depth++;
                }
                else if (token.Kind == AsnTokenKind.RightParen)
                {
                    if (depth == 1)
                    {
                        // Don't consume the closing paren — let the caller do it
                        break;
                    }

                    Next();
                    depth--;
                }
                else
                {
                    Next();
                }
            }
        }

        private void SkipToNextAssignment()
        {
            // Skip tokens until we find an identifier followed by ::= or END
            while (Peek().Kind != AsnTokenKind.EndOfFile)
            {
                if (PeekIsKeyword("END"))
                {
                    break;
                }

                // Look for pattern: Identifier ::= (start of next type assignment)
                // or lowercase-identifier TypeKeyword ::= (value assignment)
                if (Peek().Kind == AsnTokenKind.Identifier && !AsnTokenizer.IsKeyword(Peek().Value))
                {
                    // Save position conceptually — peek ahead for ::=
                    // We can't easily backtrack, so just break here and let the main loop try again
                    break;
                }

                Next();
            }
        }

        private void SkipToNextModule()
        {
            while (Peek().Kind != AsnTokenKind.EndOfFile)
            {
                if (PeekIsKeyword("END"))
                {
                    Next(); // consume END
                    break;
                }

                Next();
            }
        }
    }
}
