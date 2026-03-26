// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Kerberos.NET.Asn1CodeGen
{
    public class Asn1Lexer
    {
        private static readonly Dictionary<string, Asn1TokenType> Keywords = new(StringComparer.Ordinal)
        {
            { "SEQUENCE", Asn1TokenType.SEQUENCE },
            { "SET", Asn1TokenType.SET },
            { "CHOICE", Asn1TokenType.CHOICE },
            { "OF", Asn1TokenType.OF },
            { "BOOLEAN", Asn1TokenType.BOOLEAN },
            { "INTEGER", Asn1TokenType.INTEGER },
            { "BIT", Asn1TokenType.BIT },
            { "STRING", Asn1TokenType.STRING },
            { "OCTET", Asn1TokenType.OCTET },
            { "NULL", Asn1TokenType.NULL },
            { "OBJECT", Asn1TokenType.OBJECT },
            { "IDENTIFIER", Asn1TokenType.IDENTIFIER },
            { "ENUMERATED", Asn1TokenType.ENUMERATED },
            { "OPTIONAL", Asn1TokenType.OPTIONAL },
            { "DEFAULT", Asn1TokenType.DEFAULT },
            { "IMPLICIT", Asn1TokenType.IMPLICIT },
            { "EXPLICIT", Asn1TokenType.EXPLICIT },
            { "TAGS", Asn1TokenType.TAGS },
            { "BEGIN", Asn1TokenType.BEGIN },
            { "END", Asn1TokenType.END },
            { "DEFINITIONS", Asn1TokenType.DEFINITIONS },
            { "IMPORTS", Asn1TokenType.IMPORTS },
            { "EXPORTS", Asn1TokenType.EXPORTS },
            { "FROM", Asn1TokenType.FROM },
            { "UNIVERSAL", Asn1TokenType.UNIVERSAL },
            { "APPLICATION", Asn1TokenType.APPLICATION },
            { "PRIVATE", Asn1TokenType.PRIVATE },
            { "AUTOMATIC", Asn1TokenType.AUTOMATIC },
            { "COMPONENTS", Asn1TokenType.COMPONENTS },
            { "COMPONENT", Asn1TokenType.COMPONENT },
            { "CONTAINING", Asn1TokenType.CONTAINING },
            { "TRUE", Asn1TokenType.TRUE },
            { "FALSE", Asn1TokenType.FALSE },
            { "SIZE", Asn1TokenType.SIZE },
            { "MIN", Asn1TokenType.MIN },
            { "MAX", Asn1TokenType.MAX },
            { "UNIQUE", Asn1TokenType.UNIQUE },
            { "WITH", Asn1TokenType.WITH },
            { "ABSTRACT-SYNTAX", Asn1TokenType.ABSTRACT_SYNTAX },
            { "TYPE-IDENTIFIER", Asn1TokenType.TYPE_IDENTIFIER },
            { "GeneralizedTime", Asn1TokenType.GeneralizedTime },
            { "UTCTime", Asn1TokenType.UTCTime },
            { "UTF8String", Asn1TokenType.UTF8String },
            { "PrintableString", Asn1TokenType.PrintableString },
            { "IA5String", Asn1TokenType.IA5String },
            { "VisibleString", Asn1TokenType.VisibleString },
            { "GeneralString", Asn1TokenType.GeneralString },
            { "BMPString", Asn1TokenType.BMPString },
            { "T61String", Asn1TokenType.T61String },
            { "ANY", Asn1TokenType.ANY },
            { "DEFINED", Asn1TokenType.DEFINED },
            { "BY", Asn1TokenType.BY },
        };

        private readonly string source;
        private int pos;
        private int line = 1;
        private int col = 1;

        public Asn1Lexer(string source)
        {
            this.source = source ?? throw new ArgumentNullException(nameof(source));
        }

        public static Asn1Lexer FromFile(string path) => new(File.ReadAllText(path));

        public List<Asn1Token> Tokenize()
        {
            var tokens = new List<Asn1Token>();

            while (this.pos < this.source.Length)
            {
                this.SkipWhitespace();

                if (this.pos >= this.source.Length)
                {
                    break;
                }

                // Skip ASN.1 comments (-- ... -- or -- ... EOL)
                if (this.Peek() == '-' && this.Peek(1) == '-')
                {
                    this.SkipComment();
                    continue;
                }

                var token = this.ReadToken();

                if (token != null)
                {
                    tokens.Add(token);
                }
            }

            tokens.Add(new Asn1Token { Type = Asn1TokenType.EOF, Value = "", Line = this.line, Column = this.col });
            return tokens;
        }

        private Asn1Token ReadToken()
        {
            int startLine = this.line;
            int startCol = this.col;
            char c = this.Peek();

            // Multi-character symbols
            if (c == ':' && this.Peek(1) == ':' && this.Peek(2) == '=')
            {
                this.Advance(3);
                return new Asn1Token { Type = Asn1TokenType.Assign, Value = "::=", Line = startLine, Column = startCol };
            }

            if (c == '.' && this.Peek(1) == '.' && this.Peek(2) == '.')
            {
                this.Advance(3);
                return new Asn1Token { Type = Asn1TokenType.DotDotDot, Value = "...", Line = startLine, Column = startCol };
            }

            if (c == '.' && this.Peek(1) == '.')
            {
                this.Advance(2);
                return new Asn1Token { Type = Asn1TokenType.DotDot, Value = "..", Line = startLine, Column = startCol };
            }

            // Single-character symbols
            switch (c)
            {
                case '{': this.Advance(); return new Asn1Token { Type = Asn1TokenType.LeftBrace, Value = "{", Line = startLine, Column = startCol };
                case '}': this.Advance(); return new Asn1Token { Type = Asn1TokenType.RightBrace, Value = "}", Line = startLine, Column = startCol };
                case '[': this.Advance(); return new Asn1Token { Type = Asn1TokenType.LeftBracket, Value = "[", Line = startLine, Column = startCol };
                case ']': this.Advance(); return new Asn1Token { Type = Asn1TokenType.RightBracket, Value = "]", Line = startLine, Column = startCol };
                case '(': this.Advance(); return new Asn1Token { Type = Asn1TokenType.LeftParen, Value = "(", Line = startLine, Column = startCol };
                case ')': this.Advance(); return new Asn1Token { Type = Asn1TokenType.RightParen, Value = ")", Line = startLine, Column = startCol };
                case ',': this.Advance(); return new Asn1Token { Type = Asn1TokenType.Comma, Value = ",", Line = startLine, Column = startCol };
                case '.': this.Advance(); return new Asn1Token { Type = Asn1TokenType.Dot, Value = ".", Line = startLine, Column = startCol };
                case ';': this.Advance(); return new Asn1Token { Type = Asn1TokenType.Semicolon, Value = ";", Line = startLine, Column = startCol };
                case '|': this.Advance(); return new Asn1Token { Type = Asn1TokenType.Pipe, Value = "|", Line = startLine, Column = startCol };
            }

            // String literal
            if (c == '"')
            {
                return this.ReadStringLiteral(startLine, startCol);
            }

            // Number
            if (char.IsDigit(c))
            {
                return this.ReadNumber(startLine, startCol);
            }

            // Identifier or keyword (may contain hyphens like ABSTRACT-SYNTAX)
            if (char.IsLetter(c))
            {
                return this.ReadIdentifierOrKeyword(startLine, startCol);
            }

            // Unknown character - skip
            this.Advance();
            return null;
        }

        private Asn1Token ReadStringLiteral(int startLine, int startCol)
        {
            this.Advance(); // skip opening "
            var sb = new StringBuilder();

            while (this.pos < this.source.Length && this.Peek() != '"')
            {
                sb.Append(this.Peek());
                this.Advance();
            }

            if (this.pos < this.source.Length)
            {
                this.Advance(); // skip closing "
            }

            return new Asn1Token { Type = Asn1TokenType.String, Value = sb.ToString(), Line = startLine, Column = startCol };
        }

        private Asn1Token ReadNumber(int startLine, int startCol)
        {
            var sb = new StringBuilder();

            while (this.pos < this.source.Length && char.IsDigit(this.Peek()))
            {
                sb.Append(this.Peek());
                this.Advance();
            }

            return new Asn1Token { Type = Asn1TokenType.Number, Value = sb.ToString(), Line = startLine, Column = startCol };
        }

        private Asn1Token ReadIdentifierOrKeyword(int startLine, int startCol)
        {
            var sb = new StringBuilder();

            while (this.pos < this.source.Length &&
                   (char.IsLetterOrDigit(this.Peek()) || this.Peek() == '-'))
            {
                sb.Append(this.Peek());
                this.Advance();
            }

            string word = sb.ToString();

            if (Keywords.TryGetValue(word, out var keywordType))
            {
                return new Asn1Token { Type = keywordType, Value = word, Line = startLine, Column = startCol };
            }

            return new Asn1Token { Type = Asn1TokenType.Identifier, Value = word, Line = startLine, Column = startCol };
        }

        private void SkipWhitespace()
        {
            while (this.pos < this.source.Length && char.IsWhiteSpace(this.Peek()))
            {
                if (this.Peek() == '\n')
                {
                    this.line++;
                    this.col = 1;
                }
                else
                {
                    this.col++;
                }

                this.pos++;
            }
        }

        private void SkipComment()
        {
            // Skip "--"
            this.Advance(2);

            while (this.pos < this.source.Length)
            {
                if (this.Peek() == '-' && this.Peek(1) == '-')
                {
                    this.Advance(2);
                    return;
                }

                if (this.Peek() == '\n')
                {
                    this.line++;
                    this.col = 1;
                    this.pos++;
                    return;
                }

                this.Advance();
            }
        }

        private char Peek(int offset = 0)
        {
            int idx = this.pos + offset;
            return idx < this.source.Length ? this.source[idx] : '\0';
        }

        private void Advance(int count = 1)
        {
            for (int i = 0; i < count; i++)
            {
                if (this.pos < this.source.Length)
                {
                    this.col++;
                    this.pos++;
                }
            }
        }
    }
}
