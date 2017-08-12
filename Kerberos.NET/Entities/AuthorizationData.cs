using Kerberos.NET.Crypto;
using System.Collections.Generic;
using System.Diagnostics;
using System;
using System.IO;

#pragma warning disable S2346 // Flags enumerations zero-value members should be named "None"

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{AdType}")]
    public class AuthorizationDataElement
    {
        public AuthorizationDataElement(Asn1Element parent)
        {
            for (var i = 0; i < parent.Count; i++)
            {
                var element = parent[i];
                var child = element[0];

                switch (element.ContextSpecificTag)
                {
                    case 0:
                        AdType = child.AsLong();
                        break;
                    case 1:
                        ExtractPacData(new Asn1Element(child.Value)[0]);
                        break;
                }
            }
        }

        private void ExtractPacData(Asn1Element pacParent)
        {
            for (var i = 0; i < pacParent.Count; i++)
            {
                var ifRelevant = pacParent[i];

                switch (ifRelevant.ContextSpecificTag)
                {
                    case 0:
                        AdIfRelevant = ifRelevant[0].AsInt();
                        break;
                    case 1:
                        switch (AdIfRelevant)
                        {
                            case AD_WIN2K_PAC:
                                PrivilegedAttributeCertificate = new PrivilegedAttributeCertificate(ifRelevant[0].Value);
                                break;
                            case KERB_AUTH_DATA_TOKEN_RESTRICTIONS:
                                Restriction = new RestrictionEntry(ifRelevant[0].Value);
                                break;
                        }
                        break;
                }
            }
        }

        private const int AD_WIN2K_PAC = 128;
        private const int KERB_AUTH_DATA_TOKEN_RESTRICTIONS = 141;

        public long AdType { get; private set; }

        public byte[] AdData { get; private set; }

        public int AdIfRelevant { get; private set; }

        public PrivilegedAttributeCertificate PrivilegedAttributeCertificate { get; private set; }

        public RestrictionEntry Restriction { get; private set; }
    }

    public class RestrictionEntry
    {
        public RestrictionEntry(byte[] value)
        {
            var element = new Asn1Element(value)[0];

            for (var i = 0; i < element.Count; i++)
            {
                var entry = element[i];

                switch (entry.ContextSpecificTag)
                {
                    case 0:
                        Type = entry[0].AsInt();
                        break;
                    case 1:
                        Restriction = new LsapTokenInfoIntegrity(entry[0].Value);
                        break;
                }
            }
        }

        public int Type { get; private set; }

        public LsapTokenInfoIntegrity Restriction { get; private set; }
    }

    public class LsapTokenInfoIntegrity
    {
        public LsapTokenInfoIntegrity(byte[] value)
        {
            var reader = new BinaryReader(new MemoryStream(value));

            Flags = (TokenTypes)reader.ReadInt32();
            TokenIntegrityLevel = (IntegrityLevels)reader.ReadInt32();

            MachineId = reader.ReadBytes(32);
        }

        public TokenTypes Flags { get; private set; }

        public IntegrityLevels TokenIntegrityLevel { get; private set; }

        public byte[] MachineId { get; private set; }
    }

    [Flags]
    public enum TokenTypes
    {
        Full = 0x00000000,
        Restricted = 0x000000001
    }

    [Flags]
    public enum IntegrityLevels
    {
        Untrusted = 0x00000000,
        Low = 0x00001000,
        Medium = 0x00002000,
        High = 0x00003000,
        System = 0x00004000,
        ProtectedProcess = 0x00005000
    }

    public class AuthorizationData
    {
        protected AuthorizationData() { }

        public AuthorizationData(Asn1Element element)
        {
            for (var c = 0; c < element.Count; c++)
            {
                var child = element[c];

                Authorizations.Add(new AuthorizationDataElement(child));
            }
        }

        private List<AuthorizationDataElement> authorizations;

        public List<AuthorizationDataElement> Authorizations { get { return authorizations ?? (authorizations = new List<AuthorizationDataElement>()); } }
    }
}
