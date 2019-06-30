using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Kerberos.NET
{
    public abstract class Restriction
    {
        protected Restriction(AuthorizationDataType actualType, AuthorizationDataType expectedType)
        {
            if (actualType != expectedType)
            {
                throw new InvalidOperationException($"Cannot create {expectedType} because actual type is {actualType}");
            }

            Type = actualType;
        }

        public AuthorizationDataType Type { get; }
    }

    public class KerbServiceTargetRestriction : Restriction
    {
        public KerbServiceTargetRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbServiceTarget)
        {
            ServiceName = Encoding.Unicode.GetString(authz.Data.ToArray());
        }

        public string ServiceName { get; }
    }

    public class KerbLocalRestriction : Restriction
    {
        public KerbLocalRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbLocal)
        {
            Value = authz.Data.ToArray();
        }

        public byte[] Value { get; }
    }

    public class KerbApOptionsRestriction : Restriction
    {
        public KerbApOptionsRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbApOptions)
        {
            Options = (ApOptions)authz.Data.AsLong(littleEndian: true);
        }

        public ApOptions Options { get; }
    }

    public class KerbAuthDataTokenRestriction : Restriction
    {
        public KerbAuthDataTokenRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbAuthDataTokenRestrictions)
        {
            var restriction = KrbAuthorizationDataSequence.Decode(authz.Data);

            foreach (var data in restriction.AuthorizationData)
            {
                RestrictionType = (int)data.Type;
                Restriction = new LsapTokenInfoIntegrity(data.Data.ToArray());
                break;
            }

        }

        public int RestrictionType { get; }

        public LsapTokenInfoIntegrity Restriction { get; }
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

    public class ETypeNegotiationRestriction : Restriction
    {
        public ETypeNegotiationRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.AdETypeNegotiation)
        {
            var etypes = KrbETypeList.Decode(authz.Data);

            ETypes = new List<EncryptionType>(etypes.List);
        }

        public IEnumerable<EncryptionType> ETypes { get; }
    }
}
