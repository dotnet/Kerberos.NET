// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Humanizer;
using Kerberos.NET.Client;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Reflection;

namespace Kerberos.NET.CommandLine
{
    [CommandLineCommand("whoami", Description = "KerberosWhoAmI")]
    public class KerberosWhoAmI : BaseCommand
    {
        public KerberosWhoAmI(CommandLineParameters parameters)
            : base(parameters)
        {
        }

        [CommandLineParameter("c|cache", Description = "Cache")]
        public string Cache { get; set; }

        [CommandLineParameter("verbose", Description = "Verbose")]
        public override bool Verbose { get; protected set; }

        [CommandLineParameter("all", Description = "All")]
        public bool All { get; set; }

        [CommandLineParameter("groups", Description = "Groups")]
        public bool Groups { get; set; }

        [CommandLineParameter("logon", Description = "Logon")]
        public bool Logon { get; set; }

        [CommandLineParameter("claims", Description = "claims")]
        public bool Claims { get; set; }

        public override async Task<bool> Execute()
        {
            if (await base.Execute())
            {
                return true;
            }

            var client = this.CreateClient(verbose: this.Verbose);

            if (!string.IsNullOrWhiteSpace(this.Cache))
            {
                client.Configuration.Defaults.DefaultCCacheName = this.Cache;
            }

            await this.S4u2Self(client);

            return true;
        }

        private async Task S4u2Self(KerberosClient client)
        {
            var myTgtEntry = client.Cache.GetCacheItem<KerberosClientCacheEntry>($"krbtgt/{client.DefaultDomain}");

            var myTgt = myTgtEntry.KdcResponse?.Ticket;

            if (myTgt == null)
            {
                this.WriteHeader(SR.Resource("CommandLine_WhoAmI_NoTgt"));
                return;
            }

            var result = await client.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = client.UserPrincipalName,
                    UserToUserTicket = myTgt,
                    CacheTicket = false,
                }
            );

            var authenticator = new KerberosAuthenticator(new KerberosValidator(myTgtEntry.SessionKey.AsKey()));

            var identity = await authenticator.Authenticate(result.ApReq.EncodeApplication());

            this.DescribeTicket(identity as KerberosIdentity);
        }

        private readonly HashSet<string> IgnoredProperties = new HashSet<string>
        {
            "PacType",
            "Reserved3",
            "NameLength",
            "UpnLength",
            "UpnOffset",
            "DnsDomainNameLength",
            "DnsDomainNameOffset",
        };

        private void DescribeTicket(KerberosIdentity identity)
        {
            this.WriteLine();

            var adpac = identity.Restrictions.FirstOrDefault(r => r.Key == AuthorizationDataType.AdWin2kPac);

            var pac = (PrivilegedAttributeCertificate)adpac.Value?.FirstOrDefault();

            var properties = new List<(string, object)>()
            {
                (SR.Resource("CommandLine_WhoAmI_UserName"), $"{identity.Name}"),
            };

            if (this.All || this.Logon)
            {
                var objects = new object[]
                {
                    pac.LogonInfo,
                    pac.ClientInformation,
                    pac.DelegationInformation,
                    pac.UpnDomainInformation,
                    pac.CredentialType
                };

                foreach (var obj in objects)
                {
                    if (obj == null)
                    {
                        continue;
                    }

                    properties.Add(("", obj.GetType().Name.Humanize(LetterCasing.Title)));

                    var props = obj.GetType().GetProperties();

                    foreach (var prop in props)
                    {
                        if (!Reflect.IsEnumerable(prop.PropertyType) &&
                            !Reflect.IsBytes(prop.PropertyType) &&
                            prop.PropertyType != typeof(RpcSid) &&
                            !IgnoredProperties.Contains(prop.Name))
                        {
                            object value = prop.GetValue(obj);

                            if (value is RpcFileTime ft)
                            {
                                value = (DateTimeOffset)ft;
                            }

                            properties.Add((prop.Name.Humanize(LetterCasing.Title), value));
                        }
                    }
                }
            }

            if (this.All || this.Claims)
            {
                var others = new List<Claim>();

                foreach (var claim in identity.Claims)
                {
                    if (claim.Type == ClaimTypes.Role || claim.Type == ClaimTypes.GroupSid)
                    {
                        continue;
                    }
                    else
                    {
                        others.Add(claim);
                    }
                }

                properties.Add(("", SR.Resource("CommandLine_WhoAmI_Claims")));

                foreach (var claim in others)
                {
                    properties.Add((CollapseSchemaUrl(claim.Type), claim.Value));
                }
            }

            int max = 0;

            var propsMax = properties.Where(p => p.Item2 != null);

            if (propsMax.Any())
            {
                max = propsMax.Max(p => p.Item1.Length);

                if (max > 50)
                {
                    max = 50;
                }

                foreach (var prop in properties)
                {
                    if (string.IsNullOrWhiteSpace(prop.Item1))
                    {
                        this.WriteLine();
                        this.WriteHeader(prop.Item2.ToString());
                        this.WriteLine();
                        continue;
                    }

                    string key;

                    if (prop.Item2 == null)
                    {
                        key = SR.Resource(prop.Item1);
                    }
                    else
                    {
                        key = string.Format("{0}: ", SR.Resource(prop.Item1).PadLeft(max));
                    }

                    this.WriteLine(string.Format("  {0}{{Value}}", key), prop.Item2);
                }
            }

            if (this.All || this.Groups)
            {
                this.WriteLine();
                this.WriteHeader(SR.Resource("CommandLine_WhoAmI_Groups"));
                this.WriteLine();

                var certSids = new List<SecurityIdentifier>();

                if (pac.CredentialType != null)
                {
                    certSids.Add(SecurityIdentifier.WellKnown.ThisOrganizationCertificate);
                }

                var sids = certSids.Union(pac.LogonInfo.ExtraSids).Union(pac.LogonInfo.GroupSids).Union(pac.LogonInfo.ResourceGroups).Select(s => new
                {
                    Sid = s,
                    Name = SecurityIdentifierNames.GetFriendlyName(s.Value, pac.LogonInfo.DomainSid.Value)
                });

                max = sids.Max(s => s.Sid.Value.Length);
                var maxName = sids.Max(s => s.Name?.Length ?? 0);

                foreach (var group in sids.OrderBy(c => c.Sid.Value))
                {
                    this.WriteLine(1, string.Format("{0} {1} {{Attr}}", (group.Name ?? "").PadRight(maxName), group.Sid.Value.PadRight(max)), group.Sid.Attributes);
                }
            }
        }

        private static string CollapseSchemaUrl(string url)
        {
            var knownSchemas = new[]
            {
                "http://schemas.microsoft.com/identity/claims/",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"
            };

            var textInfo = CultureInfo.CurrentCulture.TextInfo;

            foreach (var schema in knownSchemas)
            {
                if (url.StartsWith(schema))
                {
                    return textInfo.ToTitleCase(url.Substring(schema.Length));
                }
            }

            return url;
        }
    }
}
