// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Kerberos.NET.Asn1SourceGenerator.Parser;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Asn1SourceGenerator
{
    [TestClass]
    public class TokenizerTests
    {
        // ─── Basic token types ──────────────────────────────────────

        [TestMethod]
        public void Tokenize_Assignment()
        {
            var tokenizer = new AsnTokenizer("::=");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Assignment, token.Kind);
            Assert.AreEqual("::=", token.Value);
        }

        [TestMethod]
        public void Tokenize_Ellipsis()
        {
            var tokenizer = new AsnTokenizer("...");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Ellipsis, token.Kind);
        }

        [TestMethod]
        [DataRow("{", AsnTokenKind.LeftBrace)]
        [DataRow("}", AsnTokenKind.RightBrace)]
        [DataRow("(", AsnTokenKind.LeftParen)]
        [DataRow(")", AsnTokenKind.RightParen)]
        [DataRow("[", AsnTokenKind.LeftBracket)]
        [DataRow("]", AsnTokenKind.RightBracket)]
        [DataRow(",", AsnTokenKind.Comma)]
        [DataRow(";", AsnTokenKind.Semicolon)]
        [DataRow("|", AsnTokenKind.Pipe)]
        public void Tokenize_SingleCharSymbols(string input, AsnTokenKind expectedKind)
        {
            var tokenizer = new AsnTokenizer(input);
            Assert.AreEqual(expectedKind, tokenizer.NextToken().Kind);
        }

        // ─── Identifiers and keywords ───────────────────────────────

        [TestMethod]
        public void Tokenize_Identifier()
        {
            var tokenizer = new AsnTokenizer("tkt-vno");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, token.Kind);
            Assert.AreEqual("tkt-vno", token.Value);
        }

        [TestMethod]
        public void Tokenize_Keyword_ReturnedAsIdentifier()
        {
            var tokenizer = new AsnTokenizer("SEQUENCE");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, token.Kind);
            Assert.AreEqual("SEQUENCE", token.Value);
        }

        [TestMethod]
        public void IsKeyword_RecognizesKnownKeywords()
        {
            Assert.IsTrue(AsnTokenizer.IsKeyword("SEQUENCE"));
            Assert.IsTrue(AsnTokenizer.IsKeyword("OPTIONAL"));
            Assert.IsTrue(AsnTokenizer.IsKeyword("IMPORTS"));
            Assert.IsTrue(AsnTokenizer.IsKeyword("GeneralizedTime"));
        }

        [TestMethod]
        public void IsKeyword_RejectsNonKeywords()
        {
            Assert.IsFalse(AsnTokenizer.IsKeyword("Ticket"));
            Assert.IsFalse(AsnTokenizer.IsKeyword("tkt-vno"));
            Assert.IsFalse(AsnTokenizer.IsKeyword("KrbTicket"));
        }

        // ─── Numbers ────────────────────────────────────────────────

        [TestMethod]
        public void Tokenize_PositiveNumber()
        {
            var tokenizer = new AsnTokenizer("42");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Number, token.Kind);
            Assert.AreEqual("42", token.Value);
        }

        [TestMethod]
        public void Tokenize_NegativeNumber()
        {
            var tokenizer = new AsnTokenizer("-128");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Number, token.Kind);
            Assert.AreEqual("-128", token.Value);
        }

        // ─── Comments and annotations ───────────────────────────────

        [TestMethod]
        public void Tokenize_AnnotationComment()
        {
            var tokenizer = new AsnTokenizer("-- @cs-name: TicketNumber");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.AnnotationComment, token.Kind);
            Assert.IsTrue(token.Value.Contains("@cs-name: TicketNumber"));
        }

        [TestMethod]
        public void Tokenize_MultipleAnnotationsInOneLine()
        {
            var tokenizer = new AsnTokenizer("-- @cs-name: TicketNumber @cs-type: int");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.AnnotationComment, token.Kind);
            Assert.IsTrue(token.Value.Contains("@cs-name: TicketNumber"));
            Assert.IsTrue(token.Value.Contains("@cs-type: int"));
        }

        [TestMethod]
        public void Tokenize_RegularComment_Skipped()
        {
            var tokenizer = new AsnTokenizer("-- just a comment\nSEQUENCE");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, token.Kind);
            Assert.AreEqual("SEQUENCE", token.Value);
        }

        [TestMethod]
        public void Tokenize_InlineComment_ClosedWithDoubleDash()
        {
            var tokenizer = new AsnTokenizer("-- comment -- SEQUENCE");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, token.Kind);
            Assert.AreEqual("SEQUENCE", token.Value);
        }

        [TestMethod]
        public void Tokenize_BlockComment_Skipped()
        {
            var tokenizer = new AsnTokenizer("/* block\ncomment */SEQUENCE");
            var token = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, token.Kind);
            Assert.AreEqual("SEQUENCE", token.Value);
        }

        // ─── PeekToken ──────────────────────────────────────────────

        [TestMethod]
        public void PeekToken_DoesNotConsume()
        {
            var tokenizer = new AsnTokenizer("SEQUENCE OF");
            var peeked = tokenizer.PeekToken();
            var next = tokenizer.NextToken();
            Assert.AreEqual(peeked.Kind, next.Kind);
            Assert.AreEqual(peeked.Value, next.Value);
        }

        // ─── Line/column tracking ───────────────────────────────────

        [TestMethod]
        public void Tokenize_TracksLineAndColumn()
        {
            var tokenizer = new AsnTokenizer("A\nB");
            var a = tokenizer.NextToken();
            Assert.AreEqual(1, a.Line);
            Assert.AreEqual(1, a.Column);

            var b = tokenizer.NextToken();
            Assert.AreEqual(2, b.Line);
            Assert.AreEqual(1, b.Column);
        }

        // ─── EOF ────────────────────────────────────────────────────

        [TestMethod]
        public void Tokenize_EmptyInput_ReturnsEof()
        {
            var tokenizer = new AsnTokenizer("");
            Assert.AreEqual(AsnTokenKind.EndOfFile, tokenizer.NextToken().Kind);
        }

        [TestMethod]
        public void Tokenize_UnexpectedChar_Throws()
        {
            var tokenizer = new AsnTokenizer("~");
            Assert.ThrowsException<AsnParseException>(() => tokenizer.NextToken());
        }

        // ─── Token sequence ─────────────────────────────────────────

        [TestMethod]
        public void Tokenize_TypeAssignment_ProducesCorrectSequence()
        {
            var tokenizer = new AsnTokenizer("Realm ::= GeneralString");
            var t1 = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, t1.Kind);
            Assert.AreEqual("Realm", t1.Value);

            var t2 = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Assignment, t2.Kind);

            var t3 = tokenizer.NextToken();
            Assert.AreEqual(AsnTokenKind.Identifier, t3.Kind);
            Assert.AreEqual("GeneralString", t3.Value);

            Assert.AreEqual(AsnTokenKind.EndOfFile, tokenizer.NextToken().Kind);
        }
    }
}
