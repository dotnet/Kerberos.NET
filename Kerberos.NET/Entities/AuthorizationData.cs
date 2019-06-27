using Kerberos.NET.Asn1;
using System.Collections.Generic;
using System.Diagnostics;
using System;
using System.IO;
using System.Text;
using System.Linq;
using Kerberos.NET.Crypto;

#pragma warning disable S2346 // Flags enumerations zero-value members should be named "None"

namespace Kerberos.NET.Entities
{
    public enum AuthorizationDataType : long
    {
        AdIfRelevant = 1,
        AdIntendedForServer = 2,
        AdIntendedForApplicationClass = 3,
        AdKdcIssued = 4,
        AdAndOr = 5,
        AdMandatoryTicketExtensions = 6,
        AdInTicketExtensions = 7,
        AdMandatoryForKdc = 8,
        OsfDce = 64,
        Sesame = 65,
        AdOsfDcePkiCertId = 66,
        AdWin2kPac = 128
    }

    public enum AuthorizationDataValueType
    {
        AD_WIN2K_PAC = 128,
        AD_ETYPE_NEGOTIATION = 129,
        KERB_AUTH_DATA_TOKEN_RESTRICTIONS = 141,
        KERB_LOCAL = 142,
        KERB_AP_OPTIONS = 143,
        KERB_SERVICE_TARGET = 144
    }

    [DebuggerDisplay("{Type}")]
    public abstract class AuthorizationDataElement
    {
        public abstract AuthorizationDataValueType Type { get; }

        public static IEnumerable<AuthorizationData> ParseElements(Asn1Element authData)
        {
            var dictionary = new Dictionary<AuthorizationDataType, IEnumerable<AuthorizationDataElement>>();

            AuthorizationDataType adType = 0;

            for (var i = 0; i < authData.Count; i++)
            {
                var authDataElement = authData[i];

                switch (authDataElement.ContextSpecificTag)
                {
                    case 0:
                        adType = (AuthorizationDataType)authDataElement[0].AsLong();
                        break;
                    case 1:
                        switch (adType)
                        {
                            case AuthorizationDataType.AdIfRelevant:
                                var relevant = authDataElement.AsEncapsulatedElement("Ad-if-relevant");

                                for (var r = 0; r < relevant.Count; r++)
                                {
                                    AddRestrictionType(dictionary, adType, ExtractRestrictions(relevant[r]));
                                }
                                break;
                            default:
                                Debug.WriteLine($"Unknown AdType: {adType}");
                                break;
                        }

                        break;
                }
            }

            return dictionary.Select(kv => new AuthorizationData(kv.Key, kv.Value));
        }

        private static void AddRestrictionType(
            Dictionary<AuthorizationDataType, IEnumerable<AuthorizationDataElement>> dictionary,
            AuthorizationDataType adType,
            IEnumerable<AuthorizationDataElement> elementsToAdd
        )
        {
            var elements = new List<AuthorizationDataElement>();

            if (dictionary.TryGetValue(adType, out IEnumerable<AuthorizationDataElement> existingElements))
            {
                elements = existingElements.Union(elementsToAdd).ToList();
            }
            else
            {
                elements = elementsToAdd.ToList();
            }

            dictionary[adType] = elements;
        }

        private static IEnumerable<AuthorizationDataElement> ExtractRestrictions(Asn1Element restrictions)
        {
            var elements = new List<AuthorizationDataElement>();

            AuthorizationDataValueType type = 0;

            for (var i = 0; i < restrictions.Count; i++)
            {
                switch (restrictions[i].ContextSpecificTag)
                {
                    case 0:
                        type = (AuthorizationDataValueType)restrictions[i][0].AsInt();
                        break;
                    case 1:
                        var rel = ParseAdIfRelevant(restrictions[i], type);

                        if (rel != null)
                        {
                            elements.Add(rel);
                        }
                        break;
                    default:
                        Debug.WriteLine($"Unknown restriction: {restrictions[i].ContextSpecificTag}");
                        break;
                }

            }

            return elements;
        }

        private static AuthorizationDataElement ParseAdIfRelevant(Asn1Element restriction, AuthorizationDataValueType type)
        {
            switch (type)
            {
                case AuthorizationDataValueType.AD_WIN2K_PAC:
                    return new PacElement(restriction[0].Value);
                case AuthorizationDataValueType.AD_ETYPE_NEGOTIATION:
                    return ParseETypes(restriction.AsEncapsulatedElement("ad-etype-negotiation"));
                case AuthorizationDataValueType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS:
                    return new RestrictionEntry().Decode(restriction.AsEncapsulatedElement("krb-auth-data-token-restrictions"));
                case AuthorizationDataValueType.KERB_AP_OPTIONS:
                    return new KerbApOptions(restriction[0].AsInt(reverse: true));
                case AuthorizationDataValueType.KERB_LOCAL:
                    return new KerbLocal(restriction[0].Value);
                case AuthorizationDataValueType.KERB_SERVICE_TARGET:
                    return new KerbServiceName(restriction[0].Value);
                default:
                    Debug.WriteLine($"Unknown AdIfRelevant type: {type}");
                    return null;
            }
        }

        private static NegotiatedETypes ParseETypes(Asn1Element element)
        {
            var etypes = new List<EncryptionType>();

            for (var i = 0; i < element.Count; i++)
            {
                etypes.Add((EncryptionType)element[i].AsInt());
            }

            return new NegotiatedETypes(etypes);
        }
    }

    [DebuggerDisplay("{ServiceName}")]
    public class KerbServiceName : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.KERB_SERVICE_TARGET;

        public KerbServiceName(byte[] val)
        {
            ServiceName = Encoding.Unicode.GetString(val);
        }

        public string ServiceName { get; }
    }

    public class KerbApOptions : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.KERB_AP_OPTIONS;

        public KerbApOptions(int options)
        {
            Options = (APOptions)options;
        }

        public APOptions Options { get; }
    }

    public class KerbLocal : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.KERB_LOCAL;

        public KerbLocal(byte[] val)
        {
            Value = val;
        }

        public byte[] Value { get; }
    }

    public class NegotiatedETypes : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.AD_ETYPE_NEGOTIATION;

        public NegotiatedETypes(IEnumerable<EncryptionType> types)
        {
            ETypes = types;
        }

        public IEnumerable<EncryptionType> ETypes { get; }
    }

    public class RestrictionEntry : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS;

        public RestrictionEntry Decode(Asn1Element sequence)
        {
            var element = sequence[0];

            for (var i = 0; i < element.Count; i++)
            {
                var entry = element[i];

                switch (entry.ContextSpecificTag)
                {
                    case 0:
                        RestrictionType = entry[0].AsInt();
                        break;
                    case 1:
                        Restriction = new LsapTokenInfoIntegrity(entry[0].Value);
                        break;
                    default:
                        Debug.WriteLine($"Unknown restriction {entry.ContextSpecificTag}");
                        break;
                }
            }

            return this;
        }

        public int RestrictionType;

        public LsapTokenInfoIntegrity Restriction;
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

        public TokenTypes Flags { get; }

        public IntegrityLevels TokenIntegrityLevel { get; }

        public byte[] MachineId { get; }
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

    [DebuggerDisplay("{Type}")]
    public class AuthorizationData
    {
        public AuthorizationData() { }

        public AuthorizationData(AuthorizationDataType key, IEnumerable<AuthorizationDataElement> value)
        {
            Type = key;
            authorizations = value.ToList();
        }

        public AuthorizationDataType Type { get; }

        private List<AuthorizationDataElement> authorizations;

        public IEnumerable<AuthorizationDataElement> Authorizations
        {
            get
            {
                return authorizations ?? (authorizations = new List<AuthorizationDataElement>());
            }
        }
    }
}
