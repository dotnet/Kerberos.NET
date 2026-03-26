// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Kerberos.NET.Asn1CodeGen
{
    [Generator(LanguageNames.CSharp)]
    public class Asn1IncrementalGenerator : IIncrementalGenerator
    {
        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            // Look for .asn files added as AdditionalFiles
            var asnFiles = context.AdditionalTextsProvider
                .Where(static file => file.Path.EndsWith(".asn", StringComparison.OrdinalIgnoreCase));

            // Also look for .asn.json config files
            var configFiles = context.AdditionalTextsProvider
                .Where(static file => file.Path.EndsWith(".asn.json", StringComparison.OrdinalIgnoreCase));

            // Combine asn files with config
            var asnWithConfig = asnFiles.Collect().Combine(configFiles.Collect());

            context.RegisterSourceOutput(asnWithConfig, static (spc, source) =>
            {
                var (asnTexts, configTexts) = source;

                // Load config from .asn.json files
                var config = new EmitterConfig();

                foreach (var configText in configTexts)
                {
                    var configContent = configText.GetText(spc.CancellationToken);

                    if (configContent != null)
                    {
                        MergeSimpleJsonConfig(config, configContent.ToString());
                    }
                }

                foreach (var asnText in asnTexts)
                {
                    spc.CancellationToken.ThrowIfCancellationRequested();

                    var text = asnText.GetText(spc.CancellationToken);

                    if (text == null)
                    {
                        continue;
                    }

                    try
                    {
                        var source_text = text.ToString();
                        var lexer = new Asn1Lexer(source_text);
                        var tokens = lexer.Tokenize();
                        var parser = new Asn1Parser(tokens);
                        var modules = parser.ParseAll();

                        var emitter = new CSharpCodeEmitter(modules, config);
                        var generated = emitter.EmitAll();

                        foreach (var kvp in generated)
                        {
                            string hintName = kvp.Key.Replace(".generated.cs", ".g.cs");
                            spc.AddSource(hintName, SourceText.From(kvp.Value, Encoding.UTF8));
                        }
                    }
                    catch (Asn1ParseException ex)
                    {
                        spc.ReportDiagnostic(Diagnostic.Create(
                            new DiagnosticDescriptor(
                                "ASN0001",
                                "ASN.1 Parse Error",
                                "Error parsing {0}: {1}",
                                "Asn1CodeGen",
                                DiagnosticSeverity.Error,
                                isEnabledByDefault: true),
                            Location.None,
                            Path.GetFileName(asnText.Path),
                            ex.Message));
                    }
                    catch (Exception ex)
                    {
                        spc.ReportDiagnostic(Diagnostic.Create(
                            new DiagnosticDescriptor(
                                "ASN0002",
                                "ASN.1 Code Generation Error",
                                "Error generating code from {0}: {1}",
                                "Asn1CodeGen",
                                DiagnosticSeverity.Error,
                                isEnabledByDefault: true),
                            Location.None,
                            Path.GetFileName(asnText.Path),
                            ex.Message));
                    }
                }
            });
        }

        /// <summary>
        /// Minimal JSON config parser for netstandard2.0 (no System.Text.Json).
        /// Parses the EmitterConfig format with Types, TypeConfig, FieldConfig.
        /// </summary>
        private static void MergeSimpleJsonConfig(EmitterConfig config, string json)
        {
            // Strip comments and normalize whitespace
            json = Regex.Replace(json, @"//[^\n]*", "");
            json = json.Trim();

            // Find "Types" object
            int typesStart = json.IndexOf("\"Types\"");
            if (typesStart < 0) return;

            int typesObjStart = json.IndexOf('{', typesStart + 7);
            if (typesObjStart < 0) return;

            string typesContent = ExtractBalancedBraces(json, typesObjStart);
            if (typesContent == null) return;

            // Parse each type entry: "TypeName": { ... }
            int pos = 0;
            while (pos < typesContent.Length)
            {
                int keyStart = typesContent.IndexOf('"', pos);
                if (keyStart < 0) break;

                int keyEnd = typesContent.IndexOf('"', keyStart + 1);
                if (keyEnd < 0) break;

                string typeName = typesContent.Substring(keyStart + 1, keyEnd - keyStart - 1);

                int objStart = typesContent.IndexOf('{', keyEnd);
                if (objStart < 0) break;

                string typeObj = ExtractBalancedBraces(typesContent, objStart);
                if (typeObj == null) break;

                var tc = ParseTypeConfig(typeObj);
                config.Types[typeName] = tc;

                pos = objStart + typeObj.Length + 2; // past closing brace
            }
        }

        private static TypeConfig ParseTypeConfig(string json)
        {
            var tc = new TypeConfig();

            tc.CSharpName = ExtractStringValue(json, "CSharpName");
            tc.InheritsFrom = ExtractStringValue(json, "InheritsFrom");

            string ns = ExtractStringValue(json, "Namespace");
            if (ns != null) tc.Namespace = ns;

            // Parse Fields object
            int fieldsStart = json.IndexOf("\"Fields\"");
            if (fieldsStart >= 0)
            {
                int fieldsObjStart = json.IndexOf('{', fieldsStart + 8);
                if (fieldsObjStart >= 0)
                {
                    string fieldsContent = ExtractBalancedBraces(json, fieldsObjStart);
                    if (fieldsContent != null)
                    {
                        ParseFieldConfigs(fieldsContent, tc.Fields);
                    }
                }
            }

            return tc;
        }

        private static void ParseFieldConfigs(string json, Dictionary<string, FieldConfig> fields)
        {
            int pos = 0;
            while (pos < json.Length)
            {
                int keyStart = json.IndexOf('"', pos);
                if (keyStart < 0) break;

                int keyEnd = json.IndexOf('"', keyStart + 1);
                if (keyEnd < 0) break;

                string fieldName = json.Substring(keyStart + 1, keyEnd - keyStart - 1);

                int objStart = json.IndexOf('{', keyEnd);
                if (objStart < 0) break;

                string fieldObj = ExtractBalancedBraces(json, objStart);
                if (fieldObj == null) break;

                var fc = new FieldConfig
                {
                    CSharpName = ExtractStringValue(fieldObj, "CSharpName"),
                    BackingType = ExtractStringValue(fieldObj, "BackingType"),
                    EnumType = ExtractStringValue(fieldObj, "EnumType"),
                    TreatAsEnum = ExtractBoolValue(fieldObj, "TreatAsEnum")
                };

                fields[fieldName] = fc;
                pos = objStart + fieldObj.Length + 2;
            }
        }

        private static string ExtractStringValue(string json, string key)
        {
            string pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*?)\"";
            var match = Regex.Match(json, pattern);
            return match.Success ? match.Groups[1].Value : null;
        }

        private static bool ExtractBoolValue(string json, string key)
        {
            string pattern = "\"" + key + "\"\\s*:\\s*(true|false)";
            var match = Regex.Match(json, pattern, RegexOptions.IgnoreCase);
            return match.Success && match.Groups[1].Value.Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        private static string ExtractBalancedBraces(string text, int start)
        {
            if (start >= text.Length || text[start] != '{') return null;

            int depth = 0;
            bool inString = false;

            for (int i = start; i < text.Length; i++)
            {
                char c = text[i];

                if (inString)
                {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') inString = false;
                    continue;
                }

                if (c == '"') { inString = true; continue; }
                if (c == '{') depth++;
                if (c == '}') { depth--; if (depth == 0) return text.Substring(start + 1, i - start - 1); }
            }

            return null;
        }
    }
}
