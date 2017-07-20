using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public enum CompressionFormat : ushort
    {
        COMPRESSION_FORMAT_NONE = 0,
        COMPRESSION_FORMAT_LZNT1 = 2,
        COMPRESSION_FORMAT_XPRESS = 3,
        COMPRESSION_FORMAT_XPRESS_HUFF = 4
    }

    internal static class Compressions
    {
        const ushort COMPRESSION_ENGINE_MAXIMUM = 0x100;

        [DllImport("ntdll.dll")]
        private static extern uint RtlGetCompressionWorkSpaceSize(
            ushort compressionFormat,
            ref int bufferWorkSize,
            ref int fragmentWorkSize
        );

        [DllImport("ntdll.dll")]
        private static extern uint RtlDecompressBufferEx(
            ushort compressionFormat,
            byte[] uncompressedBuffer,
            int uncompressedBufferSize,
            byte[] compressedBuffer,
            int compressedBufferSize,
            ref int finalUncompressedSize,
            byte[] workSpace
        );

        [DllImport("ntdll.dll")]
        static extern uint RtlCompressBuffer(
            ushort CompressionFormat,
            byte[] SourceBuffer,
            int SourceBufferLength,
            byte[] DestinationBuffer,
            int DestinationBufferLength,
            uint Unknown,
            out int pDestinationSize,
            byte[] WorkspaceBuffer
        );

        internal static byte[] Compress(byte[] buffer, CompressionFormat format)
        {
            var bufferWorkSize = 0;
            var fragmentWorkSize = 0;

            var compressionFormat = (ushort)((ushort)format | COMPRESSION_ENGINE_MAXIMUM);

            var result = RtlGetCompressionWorkSpaceSize(
                compressionFormat,
                ref bufferWorkSize,
                ref fragmentWorkSize
            );

            if (result != 0)
            {
                var ex = new Win32Exception((int)result);

                throw ex;
            }

            var destinationSize = 0;

            var work = new byte[bufferWorkSize];

            var compressed = new byte[bufferWorkSize];

            result = RtlCompressBuffer(
                compressionFormat,
                buffer,
                buffer.Length,
                compressed,
                compressed.Length,
                0,
                out destinationSize,
                work
            );

            if (result != 0)
            {
                var ex = new Win32Exception((int)result);

                throw ex;
            }

            Array.Resize(ref compressed, destinationSize);

            return compressed;
        }

        public static byte[] Decompress(byte[] data, long decompressedSize, CompressionFormat format)
        {
            var decompressed = new byte[decompressedSize];

            var bufferWorkSize = 0;
            var fragmentWorkSize = 0;

            var compressionFormat = (ushort)format;

            var result = RtlGetCompressionWorkSpaceSize(
                compressionFormat,
                ref bufferWorkSize,
                ref fragmentWorkSize
            );

            if (result != 0)
            {
                var ex = new Win32Exception((int)result);

                throw ex;
            }

            var work = new byte[fragmentWorkSize];

            var finalDecompressedSize = (int)decompressedSize;

            result = RtlDecompressBufferEx(
                compressionFormat,
                decompressed,
                decompressed.Length,
                data,
                data.Length,
                ref finalDecompressedSize,
                work
            );

            if (result != 0)
            {
                var ex = new Win32Exception((int)result);

                throw ex;
            }

            return decompressed;
        }
    }
}
