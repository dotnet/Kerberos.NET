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

    public class PacCredentialInfo : NdrObject
    {
        public PacCredentialInfo(byte[] info)
            : base(info)
        {
            Version = Stream.ReadInt();

            EncryptionType = (EncryptionType)Stream.ReadInt();

            SerializedData = Stream.ReadToEnd();
        }

        public int Version { get; }

        public EncryptionType EncryptionType { get; }

        public byte[] SerializedData { get; }
    }

    public class PrivilegedAttributeCertificate : NdrObject
    {
        private const int PAC_VERSION = 0;

        private byte[] signatureData;

        public PrivilegedAttributeCertificate(byte[] pac)
            : base(pac)
        {
            signatureData = new byte[pac.Length];

            Buffer.BlockCopy(pac, 0, signatureData, 0, pac.Length);

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
                var infoBuffer = new byte[size];

                Buffer.BlockCopy(pac, (int)offset, infoBuffer, 0, size);

                int exclusionStart = 0;
                int exclusionLength = 0;

                try
                {
                    ParsePacType(type, infoBuffer, out exclusionStart, out exclusionLength);
                }
                catch (Exception ex)
                {
                    errors.Add(new PacDecodeError()
                    {
                        Type = type,
                        Data = infoBuffer,
                        Exception = ex
                    });
                }

                if (exclusionStart > 0 && exclusionLength > 0)
                {
                    ZeroArray(ref signatureData, offset + exclusionStart, exclusionLength);
                }
            }

            DecodingErrors = errors;
        }

        private static void ZeroArray(ref byte[] signatureData, long start, int exclusionEnd)
        {
            for (var i = start; i < start + exclusionEnd; i++)
            {
                signatureData[i] = 0;
            }
        }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        private void ParsePacType(PacType type, byte[] infoBuffer, out int exclusionStart, out int exclusionLength)
        {
            exclusionStart = 0;
            exclusionLength = 0;

            switch (type)
            {
                case PacType.LOGON_INFO:
                    LogonInfo = new PacLogonInfo(infoBuffer);
                    break;
                case PacType.CREDENTIAL_TYPE:
                    CredentialType = new PacCredentialInfo(infoBuffer);
                    break;
                case PacType.SERVER_CHECKSUM:
                    ServerSignature = new PacSignature(infoBuffer, ref signatureData);

                    exclusionStart = ServerSignature.SignaturePosition;
                    exclusionLength = ServerSignature.Signature.Length;
                    break;
                case PacType.PRIVILEGE_SERVER_CHECKSUM:
                    KdcSignature = new PacSignature(infoBuffer, ref signatureData);

                    exclusionStart = KdcSignature.SignaturePosition;
                    exclusionLength = KdcSignature.Signature.Length;
                    break;
                case PacType.CLIENT_NAME_TICKET_INFO:
                    ClientInformation = new PacClientInfo(infoBuffer);
                    break;
                case PacType.CONSTRAINED_DELEGATION_INFO:
                    DelegationInformation = new PacDelegationInfo(infoBuffer);
                    break;
                case PacType.UPN_DOMAIN_INFO:
                    UpnDomainInformation = new UpnDomainInfo(infoBuffer);
                    break;
                case PacType.CLIENT_CLAIMS:
                    ClientClaims = new ClaimsSetMetadata(infoBuffer);
                    break;
                case PacType.DEVICE_INFO:
                    break;
                case PacType.DEVICE_CLAIMS:
                    DeviceClaims = new ClaimsSetMetadata(infoBuffer);
                    break;
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; private set; }

        public PacSignature ServerSignature { get; private set; }

        public PacCredentialInfo CredentialType { get; private set; }

        public PacSignature KdcSignature { get; private set; }

        public ClaimsSetMetadata ClientClaims { get; private set; }

        public ClaimsSetMetadata DeviceClaims { get; private set; }

        public PacClientInfo ClientInformation { get; private set; }

        public UpnDomainInfo UpnDomainInformation { get; private set; }

        public PacDelegationInfo DelegationInformation { get; private set; }
    }
}
