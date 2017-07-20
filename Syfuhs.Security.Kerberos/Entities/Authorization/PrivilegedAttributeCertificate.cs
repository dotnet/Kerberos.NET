using Syfuhs.Security.Kerberos.Entities.Authorization;
using System;
using System.IO;

namespace Syfuhs.Security.Kerberos.Entities
{
    internal class PacConstants
    {
        public const int PAC_VERSION = 0;
    }

    internal enum PacTypes
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

    public class PrivilegedAttributeCertificate
    {
        public PrivilegedAttributeCertificate(byte[] pacData)
        {
            var pacStream = new PacBinaryReader(pacData);

            var count = pacStream.ReadInt();
            var version = pacStream.ReadInt();

            if (version != PacConstants.PAC_VERSION)
            {
                throw new InvalidDataException($"Unknown PAC Version {version}");
            }

            for (var i = 0; i < count; i++)
            {
                var type = (PacTypes)pacStream.ReadInt();
                var size = pacStream.ReadInt();

                var offset = pacStream.ReadLong();
                var data = new byte[size];

                Buffer.BlockCopy(pacData, (int)offset, data, 0, size);
                
                switch (type)
                {
                    case PacTypes.LOGON_INFO:
                        LogonInfo = new PacLogonInfo(data);
                        break;
                    case PacTypes.CREDENTIAL_TYPE:
                        CredentialType = data;
                        break;
                    case PacTypes.SERVER_CHECKSUM:
                        ServerSignature = new PacSignature(data);
                        break;
                    case PacTypes.PRIVILEGE_SERVER_CHECKSUM:
                        KdcSignature = new PacSignature(data);
                        break;
                    case PacTypes.CLIENT_NAME_TICKET_INFO:
                        break;
                    case PacTypes.CONSTRAINED_DELEGATION_INFO:
                        break;
                    case PacTypes.UPN_DOMAIN_INFO:
                        break;
                    case PacTypes.CLIENT_CLAIMS:
                        ClientClaims = new ClaimsSetMetadata(data);
                        break;
                    case PacTypes.DEVICE_INFO:
                        break;
                    case PacTypes.DEVICE_CLAIMS:
                        DeviceClaims = new ClaimsSetMetadata(data);
                        break;
                }
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; private set; }

        public PacSignature ServerSignature { get; private set; }

        public byte[] CredentialType { get; private set; }

        public PacSignature KdcSignature { get; private set; }

        public ClaimsSetMetadata ClientClaims { get; private set; }

        public ClaimsSetMetadata DeviceClaims { get; private set; }
    }
}
