// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;

namespace Kerberos.NET.Asn1CodeGen
{
    /// <summary>
    /// Recursive descent parser for ASN.1 notation.
    /// Produces an AST suitable for C# code generation.
    /// Supports multiple modules per file.
    /// </summary>
    public class Asn1Parser
    {
        private readonly List<Asn1Token> tokens;
        private int pos;

        public Asn1Parser(List<Asn1Token> tokens)
        {
            this.tokens = tokens ?? throw new ArgumentNullException(nameof(tokens));
        }

        /// <summary>
        /// Parse a single module (legacy entry point).
        /// </summary>
        public Asn1Module Parse()
        {
            return this.ParseSingleModule();
        }

        /// <summary>
        /// Parse all modules in the token stream.
        /// </summary>
        public List<Asn1Module> ParseAll()
        {
            var modules = new List<Asn1Module>();

            while (this.Current.Type != Asn1TokenType.EOF)
            {
                var module = this.ParseSingleModule();
                modules.Add(module);
            }

            return modules;
        }

        private Asn1Module ParseSingleModule()
        {
            var module = new Asn1Module();

            // ModuleName [{ OID }] DEFINITIONS [TagDefault] ::= BEGIN ... END
            module.Name = this.Expect(Asn1TokenType.Identifier).Value;

            // Optional OID arc after module name
            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                module.OidComponents = this.CaptureBalanced(Asn1TokenType.LeftBrace, Asn1TokenType.RightBrace);
            }

            this.Expect(Asn1TokenType.DEFINITIONS);

            // Optional tag default
            if (this.Current.Type == Asn1TokenType.AUTOMATIC)
            {
                this.Advance();
                this.Expect(Asn1TokenType.TAGS);
                module.TagDefault = TagDefault.Automatic;
            }
            else if (this.Current.Type == Asn1TokenType.IMPLICIT)
            {
                this.Advance();
                this.Expect(Asn1TokenType.TAGS);
                module.TagDefault = TagDefault.Implicit;
            }
            else if (this.Current.Type == Asn1TokenType.EXPLICIT)
            {
                this.Advance();
                this.Expect(Asn1TokenType.TAGS);
                module.TagDefault = TagDefault.Explicit;
            }

            this.Expect(Asn1TokenType.Assign);
            this.Expect(Asn1TokenType.BEGIN);

            // Optional IMPORTS
            if (this.Current.Type == Asn1TokenType.IMPORTS)
            {
                module.Imports = this.ParseImports();
            }

            // Optional EXPORTS (skip)
            if (this.Current.Type == Asn1TokenType.EXPORTS)
            {
                this.SkipUntil(Asn1TokenType.Semicolon);
                this.Advance(); // skip ;
            }

            // Type and value assignments
            while (this.Current.Type != Asn1TokenType.END && this.Current.Type != Asn1TokenType.EOF)
            {
                this.ParseAssignment(module);
            }

            if (this.Current.Type == Asn1TokenType.END)
            {
                this.Advance();
            }

            return module;
        }

        /// <summary>
        /// Parse one assignment (type, value, or alias) and add to the module.
        /// </summary>
        private void ParseAssignment(Asn1Module module)
        {
            if (this.Current.Type != Asn1TokenType.Identifier)
            {
                this.Advance();
                return;
            }

            string name = this.Current.Value;
            this.Advance();

            // Detect value assignments: name OBJECT IDENTIFIER ::= { ... }
            if (this.Current.Type == Asn1TokenType.OBJECT)
            {
                this.Advance(); // OBJECT
                this.Expect(Asn1TokenType.IDENTIFIER); // IDENTIFIER
                this.Expect(Asn1TokenType.Assign); // ::=
                this.SkipBalanced(Asn1TokenType.LeftBrace, Asn1TokenType.RightBrace);
                return;
            }

            // Detect integer value assignments: name INTEGER ::= number
            if (this.Current.Type == Asn1TokenType.INTEGER &&
                this.Peek(1).Type == Asn1TokenType.Assign)
            {
                this.Advance(); // INTEGER
                this.Advance(); // ::=
                this.Advance(); // number
                return;
            }

            this.Expect(Asn1TokenType.Assign);

            var type = this.ParseType();

            // Determine if this is a type alias or a real type assignment
            if (this.IsTypeAlias(type))
            {
                module.TypeAliases[name] = type;
            }
            else
            {
                module.TypeAssignments.Add(new Asn1TypeAssignment
                {
                    Name = name,
                    Type = type
                });
            }
        }

        /// <summary>
        /// A type alias is a simple reference, a constrained builtin, or SEQUENCE OF a reference.
        /// Real types are SEQUENCE { fields }, CHOICE { fields }, or tagged versions of those.
        /// </summary>
        private bool IsTypeAlias(Asn1Type type)
        {
            // Direct reference: Realm ::= KerberosString
            if (type is Asn1ReferencedType)
            {
                return true;
            }

            // Simple builtins without structure: Int32 ::= INTEGER, MechType ::= OBJECT IDENTIFIER
            if (type is Asn1IntegerType || type is Asn1OctetStringType ||
                type is Asn1ObjectIdentifierType || type is Asn1GeneralizedTimeType ||
                type is Asn1UtcTimeType || type is Asn1BooleanType ||
                type is Asn1StringType || type is Asn1NullType)
            {
                return true;
            }

            // BIT STRING with named bits: KerberosFlags ::= BIT STRING (SIZE (32..MAX))
            if (type is Asn1BitStringType)
            {
                return true;
            }

            // SEQUENCE OF a reference: METHOD-DATA ::= SEQUENCE OF PA-DATA
            if (type is Asn1SequenceOfType seqOf && seqOf.ElementType is Asn1ReferencedType)
            {
                return true;
            }

            return false;
        }

        private List<Asn1Import> ParseImports()
        {
            this.Expect(Asn1TokenType.IMPORTS);
            var imports = new List<Asn1Import>();

            while (this.Current.Type != Asn1TokenType.Semicolon && this.Current.Type != Asn1TokenType.EOF)
            {
                var import = new Asn1Import();

                // Read symbols until FROM
                while (this.Current.Type != Asn1TokenType.FROM && this.Current.Type != Asn1TokenType.EOF)
                {
                    if (this.Current.Type == Asn1TokenType.Identifier || IsTypeKeyword(this.Current.Type))
                    {
                        import.Symbols.Add(this.Current.Value);
                    }

                    this.Advance();
                }

                this.Expect(Asn1TokenType.FROM);
                import.Module = this.Expect(Asn1TokenType.Identifier).Value;

                // Skip optional OID
                if (this.Current.Type == Asn1TokenType.LeftBrace)
                {
                    this.SkipBalanced(Asn1TokenType.LeftBrace, Asn1TokenType.RightBrace);
                }

                imports.Add(import);
            }

            this.Expect(Asn1TokenType.Semicolon);
            return imports;
        }

        private Asn1Type ParseType()
        {
            // Check for tagged type: [tag] IMPLICIT/EXPLICIT Type
            if (this.Current.Type == Asn1TokenType.LeftBracket)
            {
                return this.ParseTaggedType();
            }

            var type = this.ParseBuiltinOrReferencedType();

            // Check for constraint (SIZE, etc.) - skip
            if (this.Current.Type == Asn1TokenType.LeftParen)
            {
                this.SkipBalanced(Asn1TokenType.LeftParen, Asn1TokenType.RightParen);
            }

            return type;
        }

        private Asn1Type ParseTaggedType()
        {
            var tagged = new Asn1TaggedType();

            this.Expect(Asn1TokenType.LeftBracket);

            // Optional tag class
            if (this.Current.Type == Asn1TokenType.UNIVERSAL)
            {
                tagged.TagClass = TagClass.Universal;
                this.Advance();
            }
            else if (this.Current.Type == Asn1TokenType.APPLICATION)
            {
                tagged.TagClass = TagClass.Application;
                this.Advance();
            }
            else if (this.Current.Type == Asn1TokenType.PRIVATE)
            {
                tagged.TagClass = TagClass.Private;
                this.Advance();
            }

            // Tag number
            tagged.TagNumber = int.Parse(this.Expect(Asn1TokenType.Number).Value);

            this.Expect(Asn1TokenType.RightBracket);

            // Optional IMPLICIT or EXPLICIT
            if (this.Current.Type == Asn1TokenType.IMPLICIT)
            {
                tagged.Mode = TaggingMode.Implicit;
                this.Advance();
            }
            else if (this.Current.Type == Asn1TokenType.EXPLICIT)
            {
                tagged.Mode = TaggingMode.Explicit;
                this.Advance();
            }

            tagged.InnerType = this.ParseType();

            return tagged;
        }

        private Asn1Type ParseBuiltinOrReferencedType()
        {
            switch (this.Current.Type)
            {
                case Asn1TokenType.SEQUENCE:
                    return this.ParseSequenceType();

                case Asn1TokenType.SET:
                    return this.ParseSetType();

                case Asn1TokenType.CHOICE:
                    return this.ParseChoiceType();

                case Asn1TokenType.BOOLEAN:
                    this.Advance();
                    return new Asn1BooleanType();

                case Asn1TokenType.INTEGER:
                    return this.ParseIntegerType();

                case Asn1TokenType.BIT:
                    return this.ParseBitStringType();

                case Asn1TokenType.OCTET:
                    this.Advance();
                    this.Expect(Asn1TokenType.STRING);
                    return new Asn1OctetStringType();

                case Asn1TokenType.NULL:
                    this.Advance();
                    return new Asn1NullType();

                case Asn1TokenType.OBJECT:
                    this.Advance();
                    this.Expect(Asn1TokenType.IDENTIFIER);
                    return new Asn1ObjectIdentifierType();

                case Asn1TokenType.ENUMERATED:
                    return this.ParseEnumeratedType();

                case Asn1TokenType.ANY:
                    this.Advance();
                    // Skip optional DEFINED BY
                    if (this.Current.Type == Asn1TokenType.DEFINED)
                    {
                        this.Advance();
                        this.Expect(Asn1TokenType.BY);
                        this.Advance(); // skip identifier
                    }
                    return new Asn1AnyType();

                case Asn1TokenType.GeneralizedTime:
                    this.Advance();
                    return new Asn1GeneralizedTimeType();

                case Asn1TokenType.UTCTime:
                    this.Advance();
                    return new Asn1UtcTimeType();

                case Asn1TokenType.UTF8String:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.UTF8String };

                case Asn1TokenType.PrintableString:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.PrintableString };

                case Asn1TokenType.IA5String:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.IA5String };

                case Asn1TokenType.VisibleString:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.VisibleString };

                case Asn1TokenType.GeneralString:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.GeneralString };

                case Asn1TokenType.BMPString:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.BMPString };

                case Asn1TokenType.T61String:
                    this.Advance();
                    return new Asn1StringType { Kind = Asn1StringKind.T61String };

                case Asn1TokenType.Identifier:
                    var name = this.Current.Value;
                    this.Advance();
                    return new Asn1ReferencedType { ReferenceName = name };

                default:
                    throw new Asn1ParseException(
                        $"Unexpected token {this.Current.Type} ({this.Current.Value}) at {this.Current.Line}:{this.Current.Column}"
                    );
            }
        }

        private Asn1Type ParseSequenceType()
        {
            this.Expect(Asn1TokenType.SEQUENCE);

            // SEQUENCE SIZE (...) OF Type
            if (this.Current.Type == Asn1TokenType.SIZE)
            {
                this.Advance(); // SIZE
                this.SkipBalanced(Asn1TokenType.LeftParen, Asn1TokenType.RightParen);
                this.Expect(Asn1TokenType.OF);
                return new Asn1SequenceOfType { ElementType = this.ParseType() };
            }

            // SEQUENCE OF
            if (this.Current.Type == Asn1TokenType.OF)
            {
                this.Advance();
                return new Asn1SequenceOfType { ElementType = this.ParseType() };
            }

            // SEQUENCE { ... }
            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                var seq = new Asn1SequenceType();
                this.Expect(Asn1TokenType.LeftBrace);
                seq.Fields = this.ParseFieldList(ref seq);
                this.Expect(Asn1TokenType.RightBrace);
                return seq;
            }

            // Just SEQUENCE (bare reference)
            return new Asn1SequenceType();
        }

        private List<Asn1Field> ParseFieldList(ref Asn1SequenceType seqParent)
        {
            var fields = new List<Asn1Field>();

            while (this.Current.Type != Asn1TokenType.RightBrace && this.Current.Type != Asn1TokenType.EOF)
            {
                // Extension marker
                if (this.Current.Type == Asn1TokenType.DotDotDot)
                {
                    if (seqParent != null)
                    {
                        seqParent.Extensible = true;
                    }

                    this.Advance();

                    // Skip comma after ...
                    if (this.Current.Type == Asn1TokenType.Comma)
                    {
                        this.Advance();
                    }

                    continue;
                }

                // COMPONENTS OF (skip)
                if (this.Current.Type == Asn1TokenType.COMPONENTS)
                {
                    this.Advance(); // COMPONENTS
                    this.Expect(Asn1TokenType.OF);
                    this.Advance(); // type name
                    if (this.Current.Type == Asn1TokenType.Comma)
                    {
                        this.Advance();
                    }
                    continue;
                }

                var field = this.ParseField();
                fields.Add(field);

                if (this.Current.Type == Asn1TokenType.Comma)
                {
                    this.Advance();
                }
            }

            return fields;
        }

        private Asn1Field ParseField()
        {
            var field = new Asn1Field
            {
                Name = this.Expect(Asn1TokenType.Identifier).Value,
                Type = this.ParseType()
            };

            if (this.Current.Type == Asn1TokenType.OPTIONAL)
            {
                field.Optional = true;
                this.Advance();
            }
            else if (this.Current.Type == Asn1TokenType.DEFAULT)
            {
                this.Advance();
                // Read default value (simplified - just capture the token)
                field.DefaultValue = this.Current.Value;
                this.Advance();
            }

            return field;
        }

        private Asn1Type ParseSetType()
        {
            this.Expect(Asn1TokenType.SET);

            // SET SIZE (...) OF Type
            if (this.Current.Type == Asn1TokenType.SIZE)
            {
                this.Advance();
                this.SkipBalanced(Asn1TokenType.LeftParen, Asn1TokenType.RightParen);
                this.Expect(Asn1TokenType.OF);
                return new Asn1SetOfType { ElementType = this.ParseType() };
            }

            if (this.Current.Type == Asn1TokenType.OF)
            {
                this.Advance();
                return new Asn1SetOfType { ElementType = this.ParseType() };
            }

            // SET { ... } - same structure as SEQUENCE
            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                var seq = new Asn1SequenceType();
                this.Expect(Asn1TokenType.LeftBrace);
                seq.Fields = this.ParseFieldList(ref seq);
                this.Expect(Asn1TokenType.RightBrace);
                return seq;
            }

            return new Asn1SequenceType();
        }

        private Asn1Type ParseChoiceType()
        {
            this.Expect(Asn1TokenType.CHOICE);
            this.Expect(Asn1TokenType.LeftBrace);

            var choice = new Asn1ChoiceType();

            while (this.Current.Type != Asn1TokenType.RightBrace && this.Current.Type != Asn1TokenType.EOF)
            {
                if (this.Current.Type == Asn1TokenType.DotDotDot)
                {
                    choice.Extensible = true;
                    this.Advance();

                    if (this.Current.Type == Asn1TokenType.Comma)
                    {
                        this.Advance();
                    }

                    continue;
                }

                var field = this.ParseField();
                choice.Fields.Add(field);

                if (this.Current.Type == Asn1TokenType.Comma)
                {
                    this.Advance();
                }
            }

            this.Expect(Asn1TokenType.RightBrace);
            return choice;
        }

        private Asn1Type ParseIntegerType()
        {
            this.Expect(Asn1TokenType.INTEGER);

            var intType = new Asn1IntegerType();

            // Optional named numbers: INTEGER { name(value), ... }
            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                intType.NamedNumbers = this.ParseNamedNumbers();
            }

            // Optional constraint
            if (this.Current.Type == Asn1TokenType.LeftParen)
            {
                this.SkipBalanced(Asn1TokenType.LeftParen, Asn1TokenType.RightParen);
            }

            return intType;
        }

        private Asn1Type ParseBitStringType()
        {
            this.Expect(Asn1TokenType.BIT);
            this.Expect(Asn1TokenType.STRING);

            var bitString = new Asn1BitStringType();

            // Optional named bits
            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                bitString.NamedBits = this.ParseNamedNumbers();
            }

            // Optional constraint
            if (this.Current.Type == Asn1TokenType.LeftParen)
            {
                this.SkipBalanced(Asn1TokenType.LeftParen, Asn1TokenType.RightParen);
            }

            return bitString;
        }

        private Asn1Type ParseEnumeratedType()
        {
            this.Expect(Asn1TokenType.ENUMERATED);

            var enumType = new Asn1EnumeratedType();

            if (this.Current.Type == Asn1TokenType.LeftBrace)
            {
                this.Advance();
                long nextValue = 0;

                while (this.Current.Type != Asn1TokenType.RightBrace && this.Current.Type != Asn1TokenType.EOF)
                {
                    if (this.Current.Type == Asn1TokenType.DotDotDot)
                    {
                        enumType.Extensible = true;
                        this.Advance();

                        if (this.Current.Type == Asn1TokenType.Comma)
                        {
                            this.Advance();
                        }

                        continue;
                    }

                    var name = this.Expect(Asn1TokenType.Identifier).Value;
                    long value = nextValue;

                    if (this.Current.Type == Asn1TokenType.LeftParen)
                    {
                        this.Advance();
                        value = long.Parse(this.Expect(Asn1TokenType.Number).Value);
                        this.Expect(Asn1TokenType.RightParen);
                    }

                    enumType.Values.Add(new Asn1NamedNumber { Name = name, Value = value });
                    nextValue = value + 1;

                    if (this.Current.Type == Asn1TokenType.Comma)
                    {
                        this.Advance();
                    }
                }

                this.Expect(Asn1TokenType.RightBrace);
            }

            return enumType;
        }

        private List<Asn1NamedNumber> ParseNamedNumbers()
        {
            var numbers = new List<Asn1NamedNumber>();
            this.Expect(Asn1TokenType.LeftBrace);

            while (this.Current.Type != Asn1TokenType.RightBrace && this.Current.Type != Asn1TokenType.EOF)
            {
                var name = this.Expect(Asn1TokenType.Identifier).Value;
                this.Expect(Asn1TokenType.LeftParen);
                var value = long.Parse(this.Expect(Asn1TokenType.Number).Value);
                this.Expect(Asn1TokenType.RightParen);

                numbers.Add(new Asn1NamedNumber { Name = name, Value = value });

                if (this.Current.Type == Asn1TokenType.Comma)
                {
                    this.Advance();
                }
            }

            this.Expect(Asn1TokenType.RightBrace);
            return numbers;
        }

        #region Helpers

        private Asn1Token Current => this.pos < this.tokens.Count ? this.tokens[this.pos] : this.tokens[this.tokens.Count - 1];

        private Asn1Token Peek(int offset)
        {
            int idx = this.pos + offset;
            return idx < this.tokens.Count ? this.tokens[idx] : this.tokens[this.tokens.Count - 1];
        }

        private void Advance()
        {
            if (this.pos < this.tokens.Count - 1)
            {
                this.pos++;
            }
        }

        private Asn1Token Expect(Asn1TokenType type)
        {
            if (this.Current.Type != type)
            {
                throw new Asn1ParseException(
                    $"Expected {type} but got {this.Current.Type} ({this.Current.Value}) at {this.Current.Line}:{this.Current.Column}"
                );
            }

            var token = this.Current;
            this.Advance();
            return token;
        }

        private void SkipUntil(Asn1TokenType type)
        {
            while (this.Current.Type != type && this.Current.Type != Asn1TokenType.EOF)
            {
                this.Advance();
            }
        }

        private void SkipBalanced(Asn1TokenType open, Asn1TokenType close)
        {
            int depth = 0;

            do
            {
                if (this.Current.Type == open)
                {
                    depth++;
                }
                else if (this.Current.Type == close)
                {
                    depth--;
                }

                this.Advance();
            }
            while (depth > 0 && this.Current.Type != Asn1TokenType.EOF);
        }

        private string CaptureBalanced(Asn1TokenType open, Asn1TokenType close)
        {
            var parts = new List<string>();
            int depth = 0;

            do
            {
                if (this.Current.Type == open)
                {
                    depth++;
                }
                else if (this.Current.Type == close)
                {
                    depth--;
                }

                parts.Add(this.Current.Value);
                this.Advance();
            }
            while (depth > 0 && this.Current.Type != Asn1TokenType.EOF);

            return string.Join(" ", parts);
        }

        private static bool IsTypeKeyword(Asn1TokenType type) =>
            type == Asn1TokenType.BOOLEAN ||
            type == Asn1TokenType.INTEGER ||
            type == Asn1TokenType.BIT ||
            type == Asn1TokenType.OCTET ||
            type == Asn1TokenType.NULL ||
            type == Asn1TokenType.OBJECT ||
            type == Asn1TokenType.ENUMERATED ||
            type == Asn1TokenType.SEQUENCE ||
            type == Asn1TokenType.SET ||
            type == Asn1TokenType.CHOICE;

        #endregion
    }

    public class Asn1ParseException : Exception
    {
        public Asn1ParseException(string message) : base(message) { }
    }
}
