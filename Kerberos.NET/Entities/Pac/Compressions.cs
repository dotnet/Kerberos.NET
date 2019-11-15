using System;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Entities.Pac
{
    public enum CompressionFormat : ushort
    {
        COMPRESSION_FORMAT_NONE = 0,
        COMPRESSION_FORMAT_LZNT1 = 2,
        COMPRESSION_FORMAT_XPRESS = 3,
        COMPRESSION_FORMAT_XPRESS_HUFF = 4
    }

    internal unsafe static class Compressions
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
            byte* uncompressedBuffer,
            int uncompressedBufferSize,
            byte* compressedBuffer,
            int compressedBufferSize,
            ref int finalUncompressedSize,
            byte* workSpace
        );

        [DllImport("ntdll.dll")]
        static extern uint RtlCompressBuffer(
            ushort CompressionFormat,
            byte* SourceBuffer,
            int SourceBufferLength,
            byte* DestinationBuffer,
            int DestinationBufferLength,
            uint Unknown,
            out int pDestinationSize,
            byte* WorkspaceBuffer
        );

        internal static ReadOnlySpan<byte> Compress(ReadOnlySpan<byte> buffer, CompressionFormat format)
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

            var work = MemoryPool<byte>.Shared.Rent(bufferWorkSize);

            try
            {
                int destinationSize;

                var compressed = new Span<byte>(new byte[bufferWorkSize]);

                fixed (byte* pBuffer = &MemoryMarshal.GetReference(buffer))
                fixed (byte* pCompressed = &MemoryMarshal.GetReference(compressed))
                fixed (byte* pWork = &MemoryMarshal.GetReference(work.Memory.Span))
                {
                    result = RtlCompressBuffer(
                        compressionFormat,
                        pBuffer,
                        buffer.Length,
                        pCompressed,
                        compressed.Length,
                        0,
                        out destinationSize,
                        pWork
                    );
                }

                if (result != 0)
                {
                    var ex = new Win32Exception((int)result);

                    throw ex;
                }

                return compressed.Slice(0, destinationSize);
            }
            finally
            {
                work.Dispose();
            }
        }

        public static ReadOnlyMemory<byte> Decompress(ReadOnlySpan<byte> data, long decompressedSize, CompressionFormat format)
        {
            var decompressed = new Memory<byte>(new byte[decompressedSize]);

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

            var work = MemoryPool<byte>.Shared.Rent(bufferWorkSize);

            var finalDecompressedSize = (int)decompressedSize;

            try
            {
                fixed (byte* pDecompressed = &MemoryMarshal.GetReference(decompressed.Span))
                fixed (byte* pData = &MemoryMarshal.GetReference(data))
                fixed (byte* pWork = &MemoryMarshal.GetReference(work.Memory.Span))
                {
                    result = RtlDecompressBufferEx(
                        compressionFormat,
                        pDecompressed,
                        decompressed.Length,
                        pData,
                        data.Length,
                        ref finalDecompressedSize,
                        pWork
                    );

                    if (result != 0)
                    {
                        var ex = new Win32Exception((int)result);

                        throw ex;
                    }
                }

                return decompressed;
            }
            finally
            {
                work.Dispose();
            }
        }
    }
}
