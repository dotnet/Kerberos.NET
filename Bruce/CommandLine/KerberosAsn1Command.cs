// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Formats.Asn1;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kasn1|asn1|asn", Description = "KerberosAsn1")]
    public class KerberosAsn1Command : BaseCommand
    {
        public KerberosAsn1Command(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("data", FormalParameter = true, Description = "Data")]
        public string Data { get; set; }

        [CommandLineParameter("f|file", Description = "File")]
        public string InputFile { get; set; }

        [CommandLineParameter("hex", Description = "Hex")]
        public bool IsHex { get; set; }

        [CommandLineParameter("base64", Description = "Base64")]
        public bool IsBase64 { get; set; }

        [CommandLineParameter("depth", Description = "Depth")]
        public string MaxDepthStr { get; set; }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            byte[] bytes = null;

            if (!string.IsNullOrWhiteSpace(this.InputFile))
            {
                var path = Environment.ExpandEnvironmentVariables(this.InputFile);

                if (!File.Exists(path))
                {
                    this.WriteLineError("File not found: {File}", path);
                    return false;
                }

                bytes = await File.ReadAllBytesAsync(path);
            }
            else if (!string.IsNullOrWhiteSpace(this.Data))
            {
                bytes = this.ParseInput(this.Data);
            }

            if (bytes == null || bytes.Length == 0)
            {
                this.WriteLineError("No input data provided. Pass hex, base64, or use --file");
                return false;
            }

            int maxDepth = 50;

            if (!string.IsNullOrWhiteSpace(this.MaxDepthStr) && int.TryParse(this.MaxDepthStr, out int parsed))
            {
                maxDepth = parsed;
            }

            this.WriteLine();
            this.WriteHeader($"ASN.1 Structure ({bytes.Length} bytes)");
            this.WriteLine();

            try
            {
                var reader = new AsnReader(new ReadOnlyMemory<byte>(bytes), AsnEncodingRules.DER);
                this.DumpAsn1(reader, 0, maxDepth);
            }
            catch (Exception ex)
            {
                this.WriteLineError("Failed to parse ASN.1: {Error}", ex.Message);
            }

            return true;
        }

        private byte[] ParseInput(string input)
        {
            input = input.Trim();

            if (this.IsHex)
            {
                return ParseHex(input);
            }

            if (this.IsBase64)
            {
                return Convert.FromBase64String(input);
            }

            // Auto-detect
            try
            {
                return Convert.FromBase64String(input);
            }
            catch
            {
                // not base64
            }

            try
            {
                return ParseHex(input);
            }
            catch
            {
                // not hex
            }

            this.WriteLineError("Cannot parse input as base64 or hex");
            return null;
        }

        private static byte[] ParseHex(string hex)
        {
            hex = hex.Replace(" ", "").Replace("-", "").Replace(":", "").Replace("\n", "").Replace("\r", "");

            var bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return bytes;
        }

        private void DumpAsn1(AsnReader reader, int depth, int maxDepth)
        {
            if (depth > maxDepth)
            {
                this.WriteLine(depth, "... (max depth reached)");
                return;
            }

            while (reader.HasData)
            {
                var tag = reader.PeekTag();
                var indent = new string(' ', depth * 2);
                string tagName = GetTagName(tag);

                if (tag.IsConstructed)
                {
                    this.WriteLineRaw($"{indent}{tagName} {{");

                    try
                    {
                        AsnReader inner;

                        if (tag.TagClass == TagClass.ContextSpecific)
                        {
                            inner = reader.ReadSequence(tag);
                        }
                        else if (tag.TagClass == TagClass.Application)
                        {
                            inner = reader.ReadSequence(tag);
                        }
                        else
                        {
                            inner = reader.ReadSequence(tag);
                        }

                        this.DumpAsn1(inner, depth + 1, maxDepth);
                    }
                    catch
                    {
                        // fallback: read raw value
                        var raw = reader.ReadEncodedValue();
                        this.WriteLineRaw($"{indent}  ({raw.Length} bytes)");
                    }

                    this.WriteLineRaw($"{indent}}}");
                }
                else
                {
                    this.DumpPrimitive(reader, tag, indent, tagName);
                }
            }
        }

        private void DumpPrimitive(AsnReader reader, Asn1Tag tag, string indent, string tagName)
        {
            try
            {
                if (tag.TagClass == TagClass.Universal)
                {
                    switch ((UniversalTagNumber)tag.TagValue)
                    {
                        case UniversalTagNumber.Integer:
                            if (reader.TryReadInt32(out int intVal))
                            {
                                this.WriteLineRaw($"{indent}{tagName}: {intVal}");
                            }
                            else
                            {
                                var bigInt = reader.ReadIntegerBytes();
                                this.WriteLineRaw($"{indent}{tagName}: 0x{ToHexString(bigInt.Span)}");
                            }
                            return;

                        case UniversalTagNumber.Boolean:
                            this.WriteLineRaw($"{indent}{tagName}: {reader.ReadBoolean()}");
                            return;

                        case UniversalTagNumber.ObjectIdentifier:
                            var oid = reader.ReadObjectIdentifier();
                            this.WriteLineRaw($"{indent}{tagName}: {oid}");
                            return;

                        case UniversalTagNumber.OctetString:
                            var octetData = reader.ReadOctetString();
                            if (octetData.Length <= 32)
                            {
                                this.WriteLineRaw($"{indent}{tagName}: [{octetData.Length}] 0x{ToHexString(octetData)}");
                            }
                            else
                            {
                                this.WriteLineRaw($"{indent}{tagName}: [{octetData.Length} bytes]");
                            }
                            return;

                        case UniversalTagNumber.BitString:
                            var bitData = reader.ReadBitString(out int unusedBits);
                            this.WriteLineRaw($"{indent}{tagName}: [{bitData.Length} bytes, {unusedBits} unused bits]");
                            return;

                        case UniversalTagNumber.GeneralizedTime:
                            this.WriteLineRaw($"{indent}{tagName}: {reader.ReadGeneralizedTime()}");
                            return;

                        case UniversalTagNumber.Null:
                            reader.ReadNull();
                            this.WriteLineRaw($"{indent}{tagName}");
                            return;

                        case UniversalTagNumber.UTF8String:
                        case UniversalTagNumber.IA5String:
                        case UniversalTagNumber.PrintableString:
                        case UniversalTagNumber.VisibleString:
                        case UniversalTagNumber.GeneralString:
                            var str = reader.ReadCharacterString((UniversalTagNumber)tag.TagValue);
                            this.WriteLineRaw($"{indent}{tagName}: \"{str}\"");
                            return;

                        case UniversalTagNumber.Enumerated:
                            var enumBytes = reader.ReadEnumeratedBytes();
                            this.WriteLineRaw($"{indent}{tagName}: {ToHexString(enumBytes.Span)}");
                            return;
                    }
                }

                // Fallback for context-specific or unhandled primitives
                var raw = reader.ReadEncodedValue();
                this.WriteLineRaw($"{indent}{tagName}: [{raw.Length} bytes]");
            }
            catch
            {
                var raw = reader.ReadEncodedValue();
                this.WriteLineRaw($"{indent}{tagName}: [{raw.Length} bytes]");
            }
        }

        private static string GetTagName(Asn1Tag tag)
        {
            if (tag.TagClass == TagClass.ContextSpecific)
            {
                return $"[{tag.TagValue}]";
            }

            if (tag.TagClass == TagClass.Application)
            {
                string appName = tag.TagValue switch
                {
                    1 => "Ticket",
                    2 => "Authenticator",
                    3 => "EncTicketPart",
                    10 => "AS-REQ",
                    11 => "AS-REP",
                    12 => "TGS-REQ",
                    13 => "TGS-REP",
                    14 => "AP-REQ",
                    15 => "AP-REP",
                    20 => "KRB-SAFE",
                    21 => "KRB-PRIV",
                    22 => "KRB-CRED",
                    25 => "EncASRepPart",
                    26 => "EncTGSRepPart",
                    27 => "EncAPRepPart",
                    28 => "EncKrbPrivPart",
                    29 => "EncKrbCredPart",
                    30 => "KRB-ERROR",
                    _ => null
                };

                return appName != null
                    ? $"APPLICATION {tag.TagValue} ({appName})"
                    : $"APPLICATION {tag.TagValue}";
            }

            if (tag.TagClass == TagClass.Universal)
            {
                return ((UniversalTagNumber)tag.TagValue).ToString();
            }

            return $"PRIVATE {tag.TagValue}";
        }

        private static string ToHexString(ReadOnlySpan<byte> bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);

            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
