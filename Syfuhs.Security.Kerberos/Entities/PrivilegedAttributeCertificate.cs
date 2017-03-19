using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class PacSid { }

    public class PrivilegedAttributeCertificate : AuthorizationData
    {
        public PrivilegedAttributeCertificate(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        Version = node.AsLong();
                        break;
                    case 1:
                        LogonInfo = new LogonInfo(node);
                        break;
                }
            }
        }

        public long Version { get; private set; }

        public LogonInfo LogonInfo { get; private set; }
    }

    public class LogonInfo
    {
        public LogonInfo(Asn1Element node)
        {
            ;
        }

        public DateTimeOffset LogonTime { get; private set; }

        public DateTimeOffset LogoffTime { get; private set; }

        public DateTimeOffset KickOffTime { get; private set; }

        public DateTimeOffset PwdLastChangeTime { get; private set; }

        public DateTimeOffset PwdCanChangeTime { get; private set; }

        public DateTimeOffset PwdMustChangeTime { get; private set; }

        public long LogonCount { get; private set; }

        public long BadPasswordCount { get; private set; }

        public string UserName { get; private set; }

        public string UserDisplayName { get; private set; }

        public string LogonScript { get; private set; }

        public string ProfilePath { get; private set; }

        public string HomeDirectory { get; private set; }

        public string HomeDrive { get; private set; }

        public string ServerName { get; private set; }

        public string DomainName { get; private set; }

        public PacSid UserSid { get; private set; }

        public PacSid GroupSid { get; private set; }

        public List<PacSid> GroupSids { get; private set; }

        public List<PacSid> ResourceGroupSids { get; private set; }

        public List<PacSid> ExtraSids { get; private set; }

        public int UserAccountControl { get; private set; }

        public int UserFlags { get; private set; }
    }
}
