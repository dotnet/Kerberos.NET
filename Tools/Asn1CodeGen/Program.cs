// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Kerberos.NET.Asn1CodeGen
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("Usage: Asn1CodeGen <input.asn> [--output <dir>] [--config <config.json>]");
                Console.Error.WriteLine("       Asn1CodeGen <dir> [--output <dir>] [--config <config.json>]");
                return 1;
            }

            string input = args[0];
            string outputDir = null;
            string configPath = null;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--output" when i + 1 < args.Length:
                        outputDir = args[++i];
                        break;
                    case "--config" when i + 1 < args.Length:
                        configPath = args[++i];
                        break;
                }
            }

            var config = LoadConfig(configPath);

            var files = new List<string>();

            if (Directory.Exists(input))
            {
                files.AddRange(Directory.GetFiles(input, "*.asn", SearchOption.AllDirectories));
            }
            else if (File.Exists(input))
            {
                files.Add(input);
            }
            else
            {
                Console.Error.WriteLine($"Input not found: {input}");
                return 1;
            }

            if (files.Count == 0)
            {
                Console.Error.WriteLine("No .asn files found.");
                return 1;
            }

            int totalGenerated = 0;

            foreach (var file in files)
            {
                try
                {
                    string source = File.ReadAllText(file);
                    var lexer = new Asn1Lexer(source);
                    var tokens = lexer.Tokenize();
                    var parser = new Asn1Parser(tokens);
                    var modules = parser.ParseAll();

                    var emitter = new CSharpCodeEmitter(modules, config);
                    var generated = emitter.EmitAll();

                    string outDir = outputDir ?? Path.GetDirectoryName(file);

                    foreach (var kvp in generated)
                    {
                        string outPath = Path.Combine(outDir, kvp.Key);
                        string existing = File.Exists(outPath) ? File.ReadAllText(outPath) : null;

                        if (existing != kvp.Value)
                        {
                            File.WriteAllText(outPath, kvp.Value);
                            Console.WriteLine($"  Generated: {kvp.Key}");
                        }
                        else
                        {
                            Console.WriteLine($"  Unchanged: {kvp.Key}");
                        }

                        totalGenerated++;
                    }
                }
                catch (Asn1ParseException ex)
                {
                    Console.Error.WriteLine($"Parse error in {file}: {ex.Message}");
                    return 2;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error processing {file}: {ex.Message}");
                    return 3;
                }
            }

            Console.WriteLine($"Done. {totalGenerated} file(s) processed.");
            return 0;
        }

        private static EmitterConfig LoadConfig(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                return new EmitterConfig();
            }

            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<EmitterConfig>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? new EmitterConfig();
        }
    }
}
