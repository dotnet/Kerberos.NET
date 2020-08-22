// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Kerberos.NET.Entities.Pac;

#pragma warning disable IDE1006 // Naming Styles

namespace Tests.Kerberos.NET.Pac.Interop
{
    [DebuggerDisplay("{AsDateTimeOffset()}")]
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct FILETIME
    {
        public uint DwLowDateTime;

        public uint DwHighDateTime;

        public DateTimeOffset AsDateTimeOffset()
        {
            if (this.DwLowDateTime != 0xffffffffL && this.DwHighDateTime != 0x7fffffffL)
            {
                var fileTime = ((long)this.DwHighDateTime << 32) + this.DwLowDateTime;

                if (fileTime > 0)
                {
                    return DateTimeOffset.FromFileTime(fileTime);
                }
            }

            return DateTimeOffset.MinValue;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct RPC_UNICODE_STRING
    {
        public ushort Length;

        public ushort MaximumLength;

        public byte* Buffer;

        public override string ToString()
        {
            if (this.Buffer != null && this.MaximumLength > 0)
            {
                var copied = new byte[this.MaximumLength];

                Marshal.Copy((IntPtr)this.Buffer, copied, 0, this.Length);

                var span = new ReadOnlySpan<byte>(copied);

                var chars = MemoryMarshal.Cast<byte, char>(span);

                return chars.ToString();
            }

            return string.Empty;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    [DebuggerDisplay("{RelativeId} {Attributes}")]
    internal partial struct GROUP_MEMBERSHIP
    {
        public uint RelativeId;

        public SidAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct SID
    {
        public byte Revision;
        public byte SubAuthorityCount;

        public fixed byte IdentifierAuthority[6];

        public uint SubAuthority;

        public SecurityIdentifier ToSecurityIdentifier()
        {
            var auth = new uint[this.SubAuthorityCount];

            fixed (uint* pAuth = &this.SubAuthority)
            {
                for (var i = 0; i < this.SubAuthorityCount; i++)
                {
                    var val = pAuth[i];

                    auth[i] = val;
                }
            }

            long idAuth = 0;
            {
                idAuth = idAuth << 8 | this.IdentifierAuthority[0];
                idAuth = idAuth << 8 | this.IdentifierAuthority[1];
                idAuth = idAuth << 8 | this.IdentifierAuthority[2];
                idAuth = idAuth << 8 | this.IdentifierAuthority[3];
                idAuth = idAuth << 8 | this.IdentifierAuthority[4];
                idAuth = idAuth << 8 | this.IdentifierAuthority[5];
            }

            return new SecurityIdentifier((IdentifierAuthority)idAuth, auth, 0);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct KERB_SID_AND_ATTRIBUTES
    {
        public SID* Sid;
        public SidAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct KERB_VALIDATION_INFO
    {
        public FILETIME LogonTime;
        public FILETIME LogoffTime;
        public FILETIME KickOffTime;
        public FILETIME PasswordLastSet;
        public FILETIME PasswordCanChange;
        public FILETIME PasswordMustChange;
        public RPC_UNICODE_STRING EffectiveName;
        public RPC_UNICODE_STRING FullName;
        public RPC_UNICODE_STRING LogonScript;
        public RPC_UNICODE_STRING ProfilePath;
        public RPC_UNICODE_STRING HomeDirectory;
        public RPC_UNICODE_STRING HomeDirectoryDrive;

        public ushort LogonCount;
        public ushort BadPasswordCount;
        public uint UserId;
        public uint PrimaryGroupId;

        public uint GroupCount;
        public GROUP_MEMBERSHIP* GroupIds;

        public UserFlags UserFlags;

        public fixed byte UserSessionKey[16];

        public RPC_UNICODE_STRING LogonServer;
        public RPC_UNICODE_STRING LogonDomainName;

        public SID* LogonDomainId;

        public fixed int Reserved1[2];

        public UserAccountControlFlags UserAccountControl;

        public int SubAuthStatus;

        public FILETIME LastSuccessfulILogon;
        public FILETIME LastFailedILogon;
        public int FailedILogonCount;

        public int Reserved3;

        public uint SidCount;
        public KERB_SID_AND_ATTRIBUTES* ExtraSids;

        public SID* ResourceGroupDomainSid;

        public uint ResourceGroupCount;
        public GROUP_MEMBERSHIP* ResourceGroupIds;
    }
}