using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

#pragma warning disable IDE1006 // Naming Styles

namespace KerbDump
{
    public class LSASecret : IDisposable
    {
        private const string ADVAPI32 = "advapi32.dll";
        private const uint POLICY_GET_PRIVATE_INFORMATION = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern int LsaNtStatusToWinError(uint status);

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose(IntPtr policyHandle);

        [DllImport(ADVAPI32, SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory(IntPtr buffer);

        private LSA_UNICODE_STRING secretName;

        private readonly IntPtr lsaPolicyHandle;

        public LSASecret(string key)
        {
            this.secretName = new LSA_UNICODE_STRING()
            {
                Buffer = Marshal.StringToHGlobalUni(key),
                Length = (ushort)(key.Length * 2),
                MaximumLength = (ushort)((key.Length + 1) * 2)
            };

            var localsystem = default(LSA_UNICODE_STRING);
            var objectAttributes = default(LSA_OBJECT_ATTRIBUTES);

            var winErrorCode = LsaNtStatusToWinError(
                LsaOpenPolicy(
                    ref localsystem,
                    ref objectAttributes,
                    POLICY_GET_PRIVATE_INFORMATION,
                    out this.lsaPolicyHandle
                )
            );

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }

        private static void FreeMemory(IntPtr Buffer)
        {
            var winErrorCode = LsaNtStatusToWinError(LsaFreeMemory(Buffer));

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }

        public string GetSecret(out byte[] data)
        {
            var winErrorCode = LsaNtStatusToWinError(
                LsaRetrievePrivateData(this.lsaPolicyHandle, ref this.secretName, out IntPtr privateData)
            );

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }

            var lusSecretData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(privateData, typeof(LSA_UNICODE_STRING));

            data = new byte[lusSecretData.Length];

            Marshal.Copy(lusSecretData.Buffer, data, 0, lusSecretData.Length);

            FreeMemory(privateData);

            return Encoding.Unicode.GetString(data);
        }

        public void Dispose()
        {
            var winErrorCode = LsaNtStatusToWinError(LsaClose(this.lsaPolicyHandle));

            if (winErrorCode != 0)
            {
                throw new Win32Exception(winErrorCode);
            }
        }
    }
}
