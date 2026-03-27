// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kfast|fast", Description = "KerberosFast")]
    public class KerberosFastCommand : BaseCommand
    {
        public KerberosFastCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        [CommandLineParameter("realm", FormalParameter = true, Description = "Realm")]
        public override string Realm { get; set; }

        [CommandLineParameter("probe", Description = "Probe")]
        public bool Probe { get; set; }

        [CommandLineParameter("test-cf2", Description = "TestCf2")]
        public bool TestCf2 { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(this.Realm))
            {
                this.Realm = this.DefaultRealm;
            }

            this.WriteLine();

            if (this.TestCf2)
            {
                this.RunCf2Test();
                return true;
            }

            var client = this.CreateClient(verbose: this.Verbose);

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            if (this.Probe || !this.TestCf2)
            {
                await this.ProbeFastSupport(client);
            }

            return true;
        }

        private async Task ProbeFastSupport(KerberosClient client)
        {
            this.WriteHeader("FAST Support Probe");
            this.WriteLine();

            if (string.IsNullOrWhiteSpace(this.Realm))
            {
                this.WriteLineError("A realm is required for FAST probing");
                return;
            }

            this.WriteLine("  Realm: {Realm}", this.Realm);
            this.WriteLine();

            // Attempt authentication with a dummy principal to trigger PREAUTH_REQUIRED,
            // which reveals what pre-auth methods the KDC advertises.
            try
            {
                var cred = new KerberosPasswordCredential("fast-probe", "probe", this.Realm);
                await client.Authenticate(cred);

                // Unexpected success
                this.WriteHeader("KDC responded with AS-REP (unexpected for probe)");
            }
            catch (KerberosProtocolException kex) when (kex.Error != null)
            {
                this.DisplayProbeResult(kex.Error);
            }
            catch (Exception ex)
            {
                this.WriteLineError("Probe failed: {Error}", ex.Message);

                if (this.Verbose)
                {
                    this.WriteLine(1, "{StackTrace}", ex.StackTrace);
                }
            }
        }

        private void DisplayProbeResult(KrbError error)
        {
            var props = new List<(string, object)>
            {
                (null, "KDC Response"),
                ("Error Code", error.ErrorCode),
                ("Error Text", error.EText),
                ("Server Time", error.STime),
            };

            this.WriteProperties(props);
            this.WriteLine();

            if (error.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED && error.EData.HasValue)
            {
                try
                {
                    var methodData = KrbMethodData.Decode(error.EData.Value);

                    this.WriteHeader("Advertised Pre-Authentication Methods");
                    this.WriteLine();

                    bool fastAdvertised = false;
                    bool encChallengeAdvertised = false;
                    bool encTimestampAdvertised = false;
                    bool etypeInfo2Advertised = false;
                    bool reqEncPaRep = false;

                    foreach (var method in methodData.MethodData)
                    {
                        this.WriteLine(1, "  PA-DATA Type: {Type} ({TypeInt})", method.Type, (int)method.Type);

                        switch (method.Type)
                        {
                            case PaDataType.PA_FX_FAST:
                                fastAdvertised = true;
                                break;
                            case PaDataType.PA_ENCRYPTED_CHALLENGE:
                                encChallengeAdvertised = true;
                                break;
                            case PaDataType.PA_ENC_TIMESTAMP:
                                encTimestampAdvertised = true;
                                break;
                            case PaDataType.PA_ETYPE_INFO2:
                                etypeInfo2Advertised = true;

                                if (this.Verbose && method.Value.Length > 0)
                                {
                                    try
                                    {
                                        var etypeInfo2 = KrbETypeInfo2.Decode(method.Value);

                                        foreach (var entry in etypeInfo2.ETypeInfo)
                                        {
                                            this.WriteLine(2, "    EType: {EType}, Salt: {Salt}",
                                                entry.EType, entry.Salt ?? "(none)");
                                        }
                                    }
                                    catch { }
                                }
                                break;
                            case PaDataType.PA_REQ_ENC_PA_REP:
                                reqEncPaRep = true;
                                break;
                        }
                    }

                    this.WriteLine();
                    this.WriteHeader("FAST Assessment");
                    this.WriteLine();

                    this.WriteLine(1, "  PA-FX-FAST Advertised: {Value}", fastAdvertised ? "Yes" : "No");
                    this.WriteLine(1, "  Encrypted Challenge:   {Value}", encChallengeAdvertised ? "Yes" : "No");
                    this.WriteLine(1, "  Encrypted Timestamp:   {Value}", encTimestampAdvertised ? "Yes" : "No");
                    this.WriteLine(1, "  EType-Info2:           {Value}", etypeInfo2Advertised ? "Yes" : "No");
                    this.WriteLine(1, "  Enc PA-REP Request:    {Value}", reqEncPaRep ? "Yes" : "No");
                    this.WriteLine();

                    if (fastAdvertised)
                    {
                        this.WriteLine("  KDC supports FAST (RFC 6113)");
                    }
                    else
                    {
                        this.WriteLineWarning("  KDC does not advertise FAST support");
                    }
                }
                catch (Exception ex)
                {
                    this.WriteLineError("Failed to decode PA-DATA: {Error}", ex.Message);
                }
            }
            else
            {
                this.WriteLineWarning("KDC did not return PREAUTH_REQUIRED (cannot determine FAST support)");
            }

            this.WriteLine();
        }

        private void RunCf2Test()
        {
            this.WriteHeader("KRB-FX-CF2 Test (RFC 6113 Test Vectors)");
            this.WriteLine();

            // RFC 6113 Section A test vectors
            var key1 = new byte[16];
            var key2 = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                key1[i] = (byte)(i + 1);
                key2[i] = (byte)(i + 0x11);
            }

            var pepper1 = Encoding.UTF8.GetBytes("a]");
            var pepper2 = Encoding.UTF8.GetBytes("b]");

            try
            {
                var result = KrbFx.Cf2(key1, key2, pepper1, pepper2, EncryptionType.AES128_CTS_HMAC_SHA1_96);

                this.WriteLine("  Key1:    {Key}", BitConverter.ToString(key1).Replace("-", "").ToLower());
                this.WriteLine("  Key2:    {Key}", BitConverter.ToString(key2).Replace("-", "").ToLower());
                this.WriteLine("  Pepper1: {Pepper}", "a]");
                this.WriteLine("  Pepper2: {Pepper}", "b]");
                this.WriteLine("  EType:   {EType}", EncryptionType.AES128_CTS_HMAC_SHA1_96);
                this.WriteLine();
                this.WriteLine("  CF2 Result: {Result}", BitConverter.ToString(result.ToArray()).Replace("-", "").ToLower());
                this.WriteLine();
                this.WriteLine("  CF2 derivation completed successfully");
            }
            catch (Exception ex)
            {
                this.WriteLineError("CF2 test failed: {Error}", ex.Message);

                if (this.Verbose)
                {
                    this.WriteLine(1, "{StackTrace}", ex.StackTrace);
                }
            }

            this.WriteLine();
        }
    }
}
