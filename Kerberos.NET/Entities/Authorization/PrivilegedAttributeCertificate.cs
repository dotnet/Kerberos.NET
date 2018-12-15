using Kerberos.NET.Entities.Authorization;
using System;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities
{
    public enum PacType
    {
        LOGON_INFO = 1,
        CREDENTIAL_TYPE = 2,
        SERVER_CHECKSUM = 6,
        PRIVILEGE_SERVER_CHECKSUM = 7,
        CLIENT_NAME_TICKET_INFO = 0x0000000A,
        CONSTRAINED_DELEGATION_INFO = 0x0000000B,
        UPN_DOMAIN_INFO = 0x0000000C,
        CLIENT_CLAIMS = 0x0000000D,
        DEVICE_INFO = 0x0000000E,
        DEVICE_CLAIMS = 0x0000000F
    }

    public class PacElement : AuthorizationDataElement
    {
        public override AuthorizationDataValueType Type => AuthorizationDataValueType.AD_WIN2K_PAC;

        public PacElement(byte[] pacData)
        {
            Certificate = new PrivilegedAttributeCertificate(pacData);
        }

        public PrivilegedAttributeCertificate Certificate { get; }
    }

    public class PrivilegedAttributeCertificate : NdrObject
    {
        private const int PAC_VERSION = 0;

        public PrivilegedAttributeCertificate(byte[] pacData)
            : base(pacData)
        {
            var count = Stream.ReadInt();
            var version = Stream.ReadInt();

            if (version != PAC_VERSION)
            {
                throw new InvalidDataException($"Unknown PAC Version {version}");
            }

            var errors = new List<PacDecodeError>();

            for (var i = 0; i < count; i++)
            {
                var type = (PacType)Stream.ReadInt();
                var size = Stream.ReadInt();

                var offset = Stream.ReadLong();
                var data = new byte[size];

                Buffer.BlockCopy(pacData, (int)offset, data, 0, size);

                try
                {
                    ParsePacType(type, data);
                }
                catch (Exception ex)
                {
                    errors.Add(new PacDecodeError()
                    {
                        Type = type,
                        Data = data,
                        Exception = ex
                    });
                }
            }

            DecodingErrors = errors;
        }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        private void ParsePacType(PacType type, byte[] data)
        {
            switch (type)
            {
                case PacType.LOGON_INFO:
                    LogonInfo = new PacLogonInfo(data);
                    break;
                case PacType.CREDENTIAL_TYPE:
                    CredentialType = data;
                    break;
                case PacType.SERVER_CHECKSUM:
                    ServerSignature = new PacSignature(data);
                    break;
                case PacType.PRIVILEGE_SERVER_CHECKSUM:
                    KdcSignature = new PacSignature(data);
                    break;
                case PacType.CLIENT_NAME_TICKET_INFO:
                    ClientInformation = new PacClientInfo(data);
                    break;
                case PacType.CONSTRAINED_DELEGATION_INFO:
                    DelegationInformation = new PacDelegationInfo(data);
                    break;
                case PacType.UPN_DOMAIN_INFO:
                    UpnDomainInformation = new UpnDomainInfo(data);
                    break;
                case PacType.CLIENT_CLAIMS:
                    ClientClaims = new ClaimsSetMetadata(data);
                    break;
                case PacType.DEVICE_INFO:
                    break;
                case PacType.DEVICE_CLAIMS:
                    DeviceClaims = new ClaimsSetMetadata(data);
                    break;
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; private set; }

        public PacSignature ServerSignature { get; private set; }

        public byte[] CredentialType { get; private set; }

        public PacSignature KdcSignature { get; private set; }

        public ClaimsSetMetadata ClientClaims { get; private set; }

        public ClaimsSetMetadata DeviceClaims { get; private set; }

        public PacClientInfo ClientInformation { get; private set; }

        public UpnDomainInfo UpnDomainInformation { get; private set; }

        public PacDelegationInfo DelegationInformation { get; private set; }
    }
}
