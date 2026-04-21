// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Immutable;
using System.Linq;
using System.Text;
using Kerberos.NET.Asn1SourceGenerator.Emit;
using Kerberos.NET.Asn1SourceGenerator.Model;
using Kerberos.NET.Asn1SourceGenerator.Parser;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Kerberos.NET.Asn1SourceGenerator
{
    [Generator(LanguageNames.CSharp)]
    public class Asn1IncrementalGenerator : IIncrementalGenerator
    {
        public void Initialize(IncrementalGeneratorInitializationContext context)
        {
            // Collect all .asn additional files
            var asnFiles = context.AdditionalTextsProvider
                .Where(static file => file.Path.EndsWith(".asn"))
                .Select(static (file, ct) =>
                {
                    var text = file.GetText(ct)?.ToString() ?? "";
                    return (Path: file.Path, Content: text);
                })
                .Collect();

            // Generate source for all types from all .asn files
            context.RegisterSourceOutput(asnFiles, static (spc, files) =>
            {
                Execute(spc, files);
            });
        }

        private static void Execute(
            SourceProductionContext context,
            ImmutableArray<(string Path, string Content)> asnFiles)
        {
            if (asnFiles.IsDefaultOrEmpty)
            {
                return;
            }

            // Merge all .asn content into one schema parse
            var combinedAsn = new StringBuilder();
            foreach (var file in asnFiles)
            {
                combinedAsn.AppendLine(file.Content);
                combinedAsn.AppendLine();
            }

            AsnSchema schema;
            try
            {
                schema = AsnParser.Parse(combinedAsn.ToString());
            }
            catch (AsnParseException ex)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    new DiagnosticDescriptor(
                        "ASN0001",
                        "ASN.1 Parse Error",
                        "{0}",
                        "Asn1SourceGenerator",
                        DiagnosticSeverity.Error,
                        isEnabledByDefault: true),
                    Location.None,
                    ex.Message));
                return;
            }

            // Resolve types to code generation metadata
            var resolvedTypes = TypeResolver.Resolve(schema);

            // Emit C# source for each resolved type
            foreach (var resolvedType in resolvedTypes)
            {
                try
                {
                    var source = CSharpEmitter.Emit(resolvedType);
                    var hintName = $"{resolvedType.ClassName}.g.cs";
                    context.AddSource(hintName, SourceText.From(source, Encoding.UTF8));
                }
                catch (System.Exception ex)
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        new DiagnosticDescriptor(
                            "ASN0002",
                            "ASN.1 Code Generation Error",
                            "Failed to generate {0}: {1}",
                            "Asn1SourceGenerator",
                            DiagnosticSeverity.Error,
                            isEnabledByDefault: true),
                        Location.None,
                        resolvedType.ClassName,
                        ex.Message));
                }
            }
        }
    }
}
