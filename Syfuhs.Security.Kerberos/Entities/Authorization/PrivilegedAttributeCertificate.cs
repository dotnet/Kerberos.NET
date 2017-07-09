using Syfuhs.Security.Kerberos.Entities.Authorization;
using System;
using System.IO;

namespace Syfuhs.Security.Kerberos.Entities
{
    internal class PacConstants
    {
        public const int PAC_VERSION = 0;

        public const int LOGON_INFO = 1;
        public const int CREDENTIAL_TYPE = 2;
        public const int SERVER_CHECKSUM = 6;
        public const int PRIVSVR_CHECKSUM = 7;
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
                var type = pacStream.ReadInt();
                var size = pacStream.ReadInt();

                var offset = pacStream.ReadLong();
                var data = new byte[size];

                Buffer.BlockCopy(pacData, (int)offset, data, 0, size);

                switch (type)
                {
                    case PacConstants.LOGON_INFO:
                        LogonInfo = new PacLogonInfo(data);
                        break;
                    case PacConstants.CREDENTIAL_TYPE:
                        CredentialType = data;
                        break;
                    case PacConstants.SERVER_CHECKSUM:
                        ServerSignature = new PacSignature(data);
                        break;
                    case PacConstants.PRIVSVR_CHECKSUM:
                        KdcSignature = new PacSignature(data);
                        break;
                }
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; private set; }

        public PacSignature ServerSignature { get; private set; }

        public byte[] CredentialType { get; private set; }

        public PacSignature KdcSignature { get; private set; }
    }
}
