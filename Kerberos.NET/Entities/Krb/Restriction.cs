using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Kerberos.NET
{
    public abstract class Restriction
    {
        protected Restriction() { }

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

    public unsafe class KerbServiceTargetRestriction : Restriction
    {
        public KerbServiceTargetRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbServiceTarget)
        {
            ServiceName = MemoryMarshal.Cast<byte, char>(authz.Data.Span).ToString();
        }

        public string ServiceName { get; }

        public override string ToString()
        {
            return ServiceName;
        }
    }

    public class KerbLocalRestriction : Restriction
    {
        public KerbLocalRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbLocal)
        {
            Value = new ReadOnlySequence<byte>(authz.Data);
        }

        public ReadOnlySequence<byte> Value { get; }

        public override string ToString()
        {
            return Convert.ToBase64String(Value.ToArray());
        }
    }

    public class KerbApOptionsRestriction : Restriction
    {
        public KerbApOptionsRestriction(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.KerbApOptions)
        {
            Options = (ApOptions)BinaryPrimitives.ReadInt32LittleEndian(authz.Data.Span);
        }

        public ApOptions Options { get; }

        public override string ToString()
        {
            return Options.ToString();
        }
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
                Restriction = new LsapTokenInfoIntegrity(data.Data);
                break;
            }
        }

        public int RestrictionType { get; }

        public LsapTokenInfoIntegrity Restriction { get; }
    }

    public class LsapTokenInfoIntegrity
    {
        public LsapTokenInfoIntegrity(ReadOnlyMemory<byte> value)
        {
            Flags = (TokenTypes)BinaryPrimitives.ReadInt32LittleEndian(value.Span);
            TokenIntegrityLevel = (IntegrityLevels)BinaryPrimitives.ReadInt32LittleEndian(value.Span.Slice(4, 4));

            MachineId = new ReadOnlySequence<byte>(value.Slice(8, 32));
        }

        public TokenTypes Flags { get; }

        public IntegrityLevels TokenIntegrityLevel { get; }

        public ReadOnlySequence<byte> MachineId { get; }
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
