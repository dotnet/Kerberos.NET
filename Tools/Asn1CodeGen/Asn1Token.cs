// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Asn1CodeGen
{
    public enum Asn1TokenType
    {
        // Literals
        Identifier,
        Number,
        String,

        // Symbols
        Assign,         // ::=
        LeftBrace,      // {
        RightBrace,     // }
        LeftBracket,    // [
        RightBracket,   // ]
        LeftParen,      // (
        RightParen,     // )
        Comma,          // ,
        Dot,            // .
        DotDotDot,      // ...
        DotDot,         // ..
        Semicolon,      // ;
        Pipe,           // |

        // Keywords
        SEQUENCE,
        SET,
        CHOICE,
        OF,
        BOOLEAN,
        INTEGER,
        BIT,
        STRING,
        OCTET,
        NULL,
        OBJECT,
        IDENTIFIER,     // as in OBJECT IDENTIFIER
        ENUMERATED,
        OPTIONAL,
        DEFAULT,
        IMPLICIT,
        EXPLICIT,
        TAGS,
        BEGIN,
        END,
        DEFINITIONS,
        IMPORTS,
        EXPORTS,
        FROM,
        UNIVERSAL,
        APPLICATION,
        PRIVATE,
        AUTOMATIC,
        COMPONENT,
        COMPONENTS,
        CONTAINING,
        TRUE,
        FALSE,
        SIZE,
        MIN,
        MAX,
        UNIQUE,
        WITH,
        ABSTRACT_SYNTAX,
        TYPE_IDENTIFIER,
        GeneralizedTime,
        UTCTime,
        UTF8String,
        PrintableString,
        IA5String,
        VisibleString,
        GeneralString,
        BMPString,
        T61String,
        ANY,
        DEFINED,
        BY,

        // End of file
        EOF
    }

    public class Asn1Token
    {
        public Asn1TokenType Type { get; set; }
        public string Value { get; set; }
        public int Line { get; set; }
        public int Column { get; set; }

        public override string ToString() => $"{Type}({Value}) at {Line}:{Column}";
    }
}
