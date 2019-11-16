using Kerberos.NET.Entities.Pac;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

#pragma warning disable IDE1006 // Naming Styles

namespace Tests.Kerberos.NET.Pac.Interop
{
    [DebuggerDisplay("{AsDateTimeOffset()}")]
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct _FILETIME
    {
        public uint dwLowDateTime;

        public uint dwHighDateTime;

        public DateTimeOffset AsDateTimeOffset()
        {
            if (dwLowDateTime != 0xffffffffL && dwHighDateTime != 0x7fffffffL)
            {
                var fileTime = ((long)dwHighDateTime << 32) + dwLowDateTime;

                if (fileTime > 0)
                {
                    return DateTimeOffset.FromFileTime(fileTime);
                }
            }

            return DateTimeOffset.MinValue;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct _RPC_UNICODE_STRING
    {
        public ushort Length;

        public ushort MaximumLength;

        public byte* Buffer;

        public override string ToString()
        {
            if (Buffer != null && MaximumLength > 0)
            {
                var copied = new byte[MaximumLength];

                Marshal.Copy((IntPtr)Buffer, copied, 0, Length);

                var span = new ReadOnlySpan<byte>(copied);

                var chars = MemoryMarshal.Cast<byte, char>(span);

                return chars.ToString();
            }

            return string.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    [DebuggerDisplay("{RelativeId} {Attributes}")]
    internal partial struct _GROUP_MEMBERSHIP
    {
        public uint RelativeId;

        public SidAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct _SID
    {
        public byte Revision;
        public byte SubAuthorityCount;

        public fixed byte IdentifierAuthority[6];

        public uint SubAuthority;

        public SecurityIdentifier ToSecurityIdentifier()
        {
            var auth = new uint[SubAuthorityCount];

            fixed (uint* pAuth = &SubAuthority)
            {
                for (var i = 0; i < SubAuthorityCount; i++)
                {
                    var val = pAuth[i];

                    auth[i] = val;
                }
            }

            long idAuth = 0;

            {
                idAuth = idAuth << 8 | IdentifierAuthority[0];
                idAuth = idAuth << 8 | IdentifierAuthority[1];
                idAuth = idAuth << 8 | IdentifierAuthority[2];
                idAuth = idAuth << 8 | IdentifierAuthority[3];
                idAuth = idAuth << 8 | IdentifierAuthority[4];
                idAuth = idAuth << 8 | IdentifierAuthority[5];
            }

            return new SecurityIdentifier((IdentifierAuthority)idAuth, auth, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct _KERB_SID_AND_ATTRIBUTES
    {
        public _SID* Sid;
        public SidAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct KERB_VALIDATION_INFO
    {
        public _FILETIME LogonTime;
        public _FILETIME LogoffTime;
        public _FILETIME KickOffTime;
        public _FILETIME PasswordLastSet;
        public _FILETIME PasswordCanChange;
        public _FILETIME PasswordMustChange;
        public _RPC_UNICODE_STRING EffectiveName;
        public _RPC_UNICODE_STRING FullName;
        public _RPC_UNICODE_STRING LogonScript;
        public _RPC_UNICODE_STRING ProfilePath;
        public _RPC_UNICODE_STRING HomeDirectory;
        public _RPC_UNICODE_STRING HomeDirectoryDrive;

        public ushort LogonCount;
        public ushort BadPasswordCount;
        public uint UserId;
        public uint PrimaryGroupId;

        public uint GroupCount;
        public _GROUP_MEMBERSHIP* GroupIds;

        public UserFlags UserFlags;

        public fixed byte UserSessionKey[16];

        public _RPC_UNICODE_STRING LogonServer;
        public _RPC_UNICODE_STRING LogonDomainName;

        public _SID* LogonDomainId;

        public fixed int Reserved1[2];

        public UserAccountControlFlags UserAccountControl;

        public int SubAuthStatus;

        public _FILETIME LastSuccessfulILogon;
        public _FILETIME LastFailedILogon;
        public int FailedILogonCount;

        public int Reserved3;

        public uint SidCount;
        public _KERB_SID_AND_ATTRIBUTES* ExtraSids;

        public _SID* ResourceGroupDomainSid;

        public uint ResourceGroupCount;
        public _GROUP_MEMBERSHIP* ResourceGroupIds;
    }
}
