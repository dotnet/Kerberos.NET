// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;

namespace Kerberos.NET.Asn1SourceGenerator.Parser
{
    public enum AsnTokenKind
    {
        // Literals
        Identifier,
        Number,

        // Symbols
        Assignment,      // ::=
        LeftBrace,       // {
        RightBrace,      // }
        LeftParen,       // (
        RightParen,      // )
        LeftBracket,     // [
        RightBracket,    // ]
        Comma,           // ,
        Semicolon,       // ;
        Pipe,            // |
        Ellipsis,        // ...
        Dot,             // .

        // Special
        AnnotationComment,  // -- @cs-* comments
        EndOfFile,
    }

    public readonly struct AsnToken
    {
        public AsnTokenKind Kind { get; }
        public string Value { get; }
        public int Line { get; }
        public int Column { get; }

        public AsnToken(AsnTokenKind kind, string value, int line, int column)
        {
            Kind = kind;
            Value = value;
            Line = line;
            Column = column;
        }

        public override string ToString() => $"{Kind} '{Value}' at ({Line},{Column})";
    }

    public class AsnParseException : Exception
    {
        public int Line { get; }
        public int Column { get; }

        public AsnParseException(string message, int line, int column)
            : base($"ASN.1 parse error at ({line},{column}): {message}")
        {
            Line = line;
            Column = column;
        }
    }

    public class AsnTokenizer
    {
        private static readonly HashSet<string> Keywords = new HashSet<string>(StringComparer.Ordinal)
        {
            "DEFINITIONS", "BEGIN", "END",
            "SEQUENCE", "SET", "CHOICE", "OF",
            "OPTIONAL", "DEFAULT",
            "IMPORTS", "FROM",
            "EXPLICIT", "IMPLICIT", "AUTOMATIC", "TAGS",
            "APPLICATION", "UNIVERSAL", "PRIVATE",
            "BOOLEAN", "INTEGER", "BIT", "STRING", "OCTET",
            "OBJECT", "IDENTIFIER", "ENUMERATED", "NULL",
            "ANY", "DEFINED", "BY",
            "SIZE", "MAX", "MIN",
            "COMPONENTS", "WITH",
            "TRUE", "FALSE",
            "GeneralizedTime", "UTCTime",
            "GeneralString", "UTF8String", "PrintableString",
            "IA5String", "VisibleString", "T61String", "BMPString",
        };

        private readonly string _source;
        private int _position;
        private int _line;
        private int _column;
        private AsnToken? _peeked;

        public AsnTokenizer(string source)
        {
            _source = source ?? throw new ArgumentNullException(nameof(source));
            _position = 0;
            _line = 1;
            _column = 1;
        }

        public AsnToken PeekToken()
        {
            if (_peeked.HasValue)
            {
                return _peeked.Value;
            }

            _peeked = ReadNextToken();
            return _peeked.Value;
        }

        public AsnToken NextToken()
        {
            if (_peeked.HasValue)
            {
                var token = _peeked.Value;
                _peeked = null;
                return token;
            }

            return ReadNextToken();
        }

        private AsnToken ReadNextToken()
        {
            SkipWhitespace();

            if (_position >= _source.Length)
            {
                return new AsnToken(AsnTokenKind.EndOfFile, string.Empty, _line, _column);
            }

            // Block comments: /* ... */
            if (Current == '/' && Peek(1) == '*')
            {
                SkipBlockComment();
                return ReadNextToken();
            }

            // Line comments: -- ...
            if (Current == '-' && Peek(1) == '-')
            {
                return ReadComment();
            }

            // Assignment: ::=
            if (Current == ':' && Peek(1) == ':' && Peek(2) == '=')
            {
                var token = new AsnToken(AsnTokenKind.Assignment, "::=", _line, _column);
                Advance(3);
                return token;
            }

            // Ellipsis: ...
            if (Current == '.' && Peek(1) == '.' && Peek(2) == '.')
            {
                var token = new AsnToken(AsnTokenKind.Ellipsis, "...", _line, _column);
                Advance(3);
                return token;
            }

            // Single dot
            if (Current == '.')
            {
                return SingleCharToken(AsnTokenKind.Dot, ".");
            }

            // Symbols
            switch (Current)
            {
                case '{': return SingleCharToken(AsnTokenKind.LeftBrace, "{");
                case '}': return SingleCharToken(AsnTokenKind.RightBrace, "}");
                case '(': return SingleCharToken(AsnTokenKind.LeftParen, "(");
                case ')': return SingleCharToken(AsnTokenKind.RightParen, ")");
                case '[': return SingleCharToken(AsnTokenKind.LeftBracket, "[");
                case ']': return SingleCharToken(AsnTokenKind.RightBracket, "]");
                case ',': return SingleCharToken(AsnTokenKind.Comma, ",");
                case ';': return SingleCharToken(AsnTokenKind.Semicolon, ";");
                case '|': return SingleCharToken(AsnTokenKind.Pipe, "|");
            }

            // Numbers (including negative)
            if (IsDigit(Current) || (Current == '-' && _position + 1 < _source.Length && IsDigit(_source[_position + 1])))
            {
                return ReadNumber();
            }

            // Identifiers and keywords
            if (IsIdentifierStart(Current))
            {
                return ReadIdentifier();
            }

            throw new AsnParseException($"Unexpected character '{Current}'", _line, _column);
        }

        private AsnToken SingleCharToken(AsnTokenKind kind, string value)
        {
            var token = new AsnToken(kind, value, _line, _column);
            Advance(1);
            return token;
        }

        private AsnToken ReadComment()
        {
            int startLine = _line;
            int startColumn = _column;

            // Skip the opening '--'
            Advance(2);

            int contentStart = _position;

            // ASN.1 comments end at the next '--' or end of line.
            // Scan for a closing '--' on the same line first.
            bool closedInline = false;
            while (_position < _source.Length && Current != '\n' && Current != '\r')
            {
                if (Current == '-' && Peek(1) == '-')
                {
                    // Found closing '--' — end the comment here
                    closedInline = true;
                    break;
                }
                _position++;
                _column++;
            }

            string content = _source.Substring(contentStart, _position - contentStart);

            if (closedInline)
            {
                // Skip the closing '--'
                Advance(2);
            }

            // Check for annotation comment: starts with " @cs-"
            if (content.TrimStart().StartsWith("@cs-"))
            {
                return new AsnToken(AsnTokenKind.AnnotationComment, content.TrimStart(), startLine, startColumn);
            }

            // Regular comment — skip and read next token
            return ReadNextToken();
        }

        private void SkipBlockComment()
        {
            // Skip '/*'
            Advance(2);

            while (_position < _source.Length)
            {
                if (Current == '*' && Peek(1) == '/')
                {
                    Advance(2);
                    return;
                }

                if (Current == '\n')
                {
                    _line++;
                    _column = 1;
                    _position++;
                }
                else if (Current == '\r')
                {
                    _line++;
                    _column = 1;
                    _position++;

                    if (_position < _source.Length && Current == '\n')
                    {
                        _position++;
                    }
                }
                else
                {
                    _position++;
                    _column++;
                }
            }

            throw new AsnParseException("Unterminated block comment", _line, _column);
        }

        private AsnToken ReadNumber()
        {
            int startLine = _line;
            int startColumn = _column;
            int start = _position;

            if (Current == '-')
            {
                _position++;
                _column++;
            }

            if (_position >= _source.Length || !IsDigit(Current))
            {
                throw new AsnParseException("Expected digit after '-'", _line, _column);
            }

            while (_position < _source.Length && IsDigit(Current))
            {
                _position++;
                _column++;
            }

            string value = _source.Substring(start, _position - start);
            return new AsnToken(AsnTokenKind.Number, value, startLine, startColumn);
        }

        private AsnToken ReadIdentifier()
        {
            int startLine = _line;
            int startColumn = _column;
            int start = _position;

            // First character is already validated as identifier start
            _position++;
            _column++;

            // ASN.1 identifiers may contain letters, digits, and hyphens.
            // A hyphen must not be the last character, but we accept it
            // during lexing and let the parser enforce stricter rules.
            while (_position < _source.Length && IsIdentifierContinuation(Current))
            {
                _position++;
                _column++;
            }

            // Trim any trailing hyphens (e.g., malformed input)
            int end = _position;
            while (end > start + 1 && _source[end - 1] == '-')
            {
                end--;
                _position--;
                _column--;
            }

            string value = _source.Substring(start, end - start);

            // Both keywords and regular identifiers use the Identifier token kind.
            // The parser distinguishes keywords from identifiers by value.
            return new AsnToken(AsnTokenKind.Identifier, value, startLine, startColumn);
        }

        private void SkipWhitespace()
        {
            while (_position < _source.Length)
            {
                char c = Current;

                if (c == '\n')
                {
                    _position++;
                    _line++;
                    _column = 1;
                }
                else if (c == '\r')
                {
                    _position++;
                    _line++;
                    _column = 1;

                    if (_position < _source.Length && Current == '\n')
                    {
                        _position++;
                    }
                }
                else if (c == ' ' || c == '\t')
                {
                    _position++;
                    _column++;
                }
                else
                {
                    break;
                }
            }
        }

        private char Current => _source[_position];

        private char Peek(int offset)
        {
            int index = _position + offset;
            return index < _source.Length ? _source[index] : '\0';
        }

        private void Advance(int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (_position < _source.Length)
                {
                    _position++;
                    _column++;
                }
            }
        }

        private static bool IsDigit(char c) => c >= '0' && c <= '9';

        private static bool IsLetter(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');

        private static bool IsIdentifierStart(char c) => IsLetter(c);

        private static bool IsIdentifierContinuation(char c) => IsLetter(c) || IsDigit(c) || c == '-';

        /// <summary>
        /// Returns whether the given identifier text is a recognized ASN.1 keyword.
        /// </summary>
        public static bool IsKeyword(string identifier) => Keywords.Contains(identifier);
    }
}
