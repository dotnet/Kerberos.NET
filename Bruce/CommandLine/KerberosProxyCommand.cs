// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("kproxy|proxy", Description = "KerberosProxy")]
    public class KerberosProxyCommand : BaseCommand
    {
        public KerberosProxyCommand(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("realm", FormalParameter = true, Description = "Realm")]
        public override string Realm { get; set; }

        [CommandLineParameter("v|verbose", Description = "Verbose")]
        public override bool Verbose { get; set; }

        [CommandLineParameter("url", Description = "Url")]
        public string ProxyUrl { get; set; }

        [CommandLineParameter("timeout", Description = "Timeout")]
        public TimeSpan? Timeout { get; set; }

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

            if (string.IsNullOrWhiteSpace(this.Realm))
            {
                this.WriteLineError("A realm is required. Specify as a parameter or set USERDNSDOMAIN.");
                return false;
            }

            this.WriteLine();
            this.WriteHeader("KDC Proxy Connectivity Test");
            this.WriteLine();

            await this.TestProxyConnectivity();

            return true;
        }

        private async Task TestProxyConnectivity()
        {
            var timeout = this.Timeout ?? TimeSpan.FromSeconds(10);

            using var cts = new CancellationTokenSource(timeout);

            var transport = new HttpsKerberosTransport();
            transport.ConnectTimeout = timeout;

            if (!string.IsNullOrWhiteSpace(this.ProxyUrl))
            {
                transport.DomainPaths[this.Realm.ToLowerInvariant()] = new Uri(this.ProxyUrl);
            }

            this.WriteLine("  Realm: {Realm}", this.Realm);

            if (!string.IsNullOrWhiteSpace(this.ProxyUrl))
            {
                this.WriteLine("  Proxy URL: {Url}", this.ProxyUrl);
            }
            else
            {
                this.WriteLine("  Discovery: DNS SRV (_kerberos._https)");
            }

            this.WriteLine("  Timeout: {Timeout}", timeout);
            this.WriteLine();

            // Build a minimal AS-REQ to probe the KDC proxy
            var asReq = new KrbAsReq
            {
                Body = new KrbKdcReqBody
                {
                    CName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = new[] { "probe" }
                    },
                    Realm = this.Realm.ToUpperInvariant(),
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", this.Realm.ToUpperInvariant() }
                    },
                    Till = DateTimeOffset.UtcNow.AddHours(1),
                    Nonce = (int)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() & 0x7FFFFFFF),
                    EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96 },
                }
            };

            var encoded = asReq.EncodeApplication();

            var sw = Stopwatch.StartNew();

            try
            {
                var response = await transport.SendMessage(
                    this.Realm,
                    encoded,
                    cts.Token
                );

                sw.Stop();

                this.WriteHeader("Result: Connected");
                this.WriteLine();
                this.WriteLine("  Response Size: {Size} bytes", response.Length);
                this.WriteLine("  Round Trip: {Time}ms", sw.ElapsedMilliseconds);

                if (!string.IsNullOrWhiteSpace(transport.RequestId))
                {
                    this.WriteLine("  Request ID: {RequestId}", transport.RequestId);
                }

                // Try to decode the response as a KRB-ERROR (expected for a probe)
                try
                {
                    var error = KrbError.DecodeApplication(response);

                    var errorProps = new List<(string, object)>
                    {
                        ("", ""),
                        (null, "KDC Response"),
                        ("Error Code", error.ErrorCode),
                        ("Error Text", error.EText),
                        ("Server Time", error.STime),
                        ("Realm", error.Realm),
                    };

                    this.WriteProperties(errorProps);
                }
                catch
                {
                    if (this.Verbose)
                    {
                        this.WriteLine("  (Response is not a KRB-ERROR)");
                    }
                }
            }
            catch (KerberosTransportException tex)
            {
                sw.Stop();

                this.WriteLineError("Transport Error: {Error}", tex.Message);
                this.WriteLine();
                this.WriteLine("  Time Elapsed: {Time}ms", sw.ElapsedMilliseconds);

                if (tex.Error != null)
                {
                    this.WriteLine("  KDC Error: {Error}", tex.Error.ErrorCode);
                }
            }
            catch (HttpRequestException hex)
            {
                sw.Stop();

                this.WriteLineError("HTTP Error: {Error}", hex.Message);
                this.WriteLine();
                this.WriteLine("  Time Elapsed: {Time}ms", sw.ElapsedMilliseconds);
            }
            catch (OperationCanceledException)
            {
                sw.Stop();

                this.WriteLineError("Connection timed out after {Timeout}", timeout);
                this.WriteLine();
                this.WriteLine("  Time Elapsed: {Time}ms", sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();

                this.WriteLineError("Error: {Error}", ex.Message);

                if (this.Verbose)
                {
                    this.WriteLine(1, "{StackTrace}", ex.StackTrace);
                }
            }

            this.WriteLine();
        }
    }
}
