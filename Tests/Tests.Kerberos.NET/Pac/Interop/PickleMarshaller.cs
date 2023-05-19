// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Tests.Kerberos.NET.Pac.Interop
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate IntPtr PfnAllocate(int s);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void PfnFree(IntPtr f);

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct MIDL_TYPE_PICKLING_INFO
    {
        public uint Version;

        public uint Flags;

        public fixed uint Reserved[3];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RPC_CLIENT_INTERFACE
    {
        public uint Length;

        public RPC_SYNTAX_IDENTIFIER InterfaceId;

        public RPC_SYNTAX_IDENTIFIER TransferSyntax;

        public IntPtr DispatchTable;

        public uint RpcProtseqEndpointCount;

        public IntPtr RpcProtseqEndpoint;

        public uint Reserved;

        public IntPtr InterpreterInfo;

        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIDL_STUB_DESC
    {
        public IntPtr RpcInterfaceInformation;
        public IntPtr PfnAllocate;
        public IntPtr PfnFree;
        public IntPtr PHandle;

        public IntPtr ApfnNdrRundownRoutines;
        public IntPtr AGenericBindingRoutinePairs;
        public IntPtr ApfnExprEval;
        public IntPtr AXmitQuintuple;

        public IntPtr PFormatTypes;

        public int FCheckBounds;
        public uint Version;
        public IntPtr PMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        public IntPtr AUserMarshalQuadruple;
        public IntPtr NotifyRoutineTable;
        public uint MFlags;
        public IntPtr CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr PExprInfo;
    }

    internal unsafe sealed class PickleMarshaller : IDisposable
    {
        private const int RpcSOk = 0;

        private static readonly PfnAllocate FnAllocator = new(MIDL_user_allocate);
        private static readonly PfnFree FnFree = new(MIDL_user_free);

        private static readonly MIDL_TYPE_PICKLING_INFO MIDLTypePicklingInfo = new()
        {
            Version = 0x33205054,
            Flags = 0x3
        };

        private static readonly RPC_CLIENT_INTERFACE RpcClientInterface = new()
        {
            Length = (uint)sizeof(RPC_CLIENT_INTERFACE),
            InterfaceId = new RPC_SYNTAX_IDENTIFIER()
            {
                SyntaxGUID = new Guid(0x906B0CE0, 0xC70B, 0x1067, 0xB3, 0x17, 0x00, 0xDD, 0x01, 0x06, 0x62, 0xDA),
                SyntaxVersion = new RPC_VERSION
                {
                    MajorVersion = 1,
                    MinorVersion = 0
                }
            },
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER
            {
                SyntaxGUID = new Guid(0x8A885D04, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60),
                SyntaxVersion = new RPC_VERSION()
                {
                    MajorVersion = 2,
                    MinorVersion = 0
                }
            }
        };

        private readonly int formatOffset;

        private readonly MemoryHandle pTypeFormatString;
        private readonly GCHandle pRpcInterface;

        private bool disposed;
        private MIDL_STUB_DESC stubDesc;

        public unsafe PickleMarshaller(ReadOnlyMemory<byte> typeFormatString, int formatOffset)
        {
            this.pTypeFormatString = typeFormatString.Pin();
            this.pRpcInterface = GCHandle.Alloc(RpcClientInterface, GCHandleType.Pinned);

            this.formatOffset = formatOffset;

            this.stubDesc = new MIDL_STUB_DESC
            {
                RpcInterfaceInformation = this.pRpcInterface.AddrOfPinnedObject(),
                PfnAllocate = Marshal.GetFunctionPointerForDelegate(FnAllocator),
                PfnFree = Marshal.GetFunctionPointerForDelegate(FnFree),
                PFormatTypes = (IntPtr)this.pTypeFormatString.Pointer,
                FCheckBounds = 1,
                Version = 0x60000,
                MIDLVersion = 0x8000000,
                MFlags = 0x1
            };
        }

        public unsafe SafeMarshalledHandle<T> Decode<T>(ReadOnlySpan<byte> buffer, Func<IntPtr, T> converter)
        {
            // WARNING: THIS IS DANGEROUS
            //
            // THIS CAN BE INCREDIBLY LEAKY BECAUSE IT DOESN'T FREE BUFFERS
            // DO NOT FORGET TO FREE THE HANDLE AFTER YOU"VE USED IT

            if (this.disposed)
            {
                throw new ObjectDisposedException(nameof(PickleMarshaller));
            }

            IntPtr pObj = IntPtr.Zero;

            fixed (void* pBuf = &MemoryMarshal.GetReference(buffer))
            {
                var ret = MesDecodeBufferHandleCreate(
                    pBuf,
                    buffer.Length,
                    out IntPtr ndrHandle
               );

                if (ret != RpcSOk)
                {
                    throw new Win32Exception(ret);
                }

                fixed (MIDL_TYPE_PICKLING_INFO* pPicklingInfo = &MIDLTypePicklingInfo)
                {
                    NdrMesTypeDecode2(
                         ndrHandle,
                         pPicklingInfo,
                         ref this.stubDesc,
                         this.stubDesc.PFormatTypes + this.formatOffset,
                         ref pObj
                   );
                }

                if (pObj == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return new SafeMarshalledHandle<T>(converter(pObj), () => this.FreeNdr(ref ndrHandle, ref pObj));
            }
        }

        private unsafe void FreeNdr(ref IntPtr ndrHandle, ref IntPtr pObj)
        {
            fixed (MIDL_TYPE_PICKLING_INFO* pPicklingInfo = &MIDLTypePicklingInfo)
            {
                NdrMesTypeFree2(
                    ndrHandle,
                    pPicklingInfo,
                    ref this.stubDesc,
                    this.stubDesc.PFormatTypes + this.formatOffset,
                    ref pObj
               );
            }

            var ret = MesHandleFree(ndrHandle);

            if (ret != RpcSOk)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        [DllImport("rpcrt4.dll")]
        private static unsafe extern int MesDecodeBufferHandleCreate(
            void* pBuffer,
            int bufferSize,
            out IntPtr pHandle
       );

        [DllImport("rpcrt4.dll")]
        private static unsafe extern void NdrMesTypeDecode2(
            IntPtr handle,
            MIDL_TYPE_PICKLING_INFO* pPicklingInfo,
            ref MIDL_STUB_DESC pStubDesc,
            IntPtr pFormatString,
            ref IntPtr pObject
       );

        [DllImport("rpcrt4.dll")]
        private static unsafe extern void NdrMesTypeEncode2(
            IntPtr handle,
            MIDL_TYPE_PICKLING_INFO* pPicklingInfo,
            ref MIDL_STUB_DESC pStubDesc,
            IntPtr pFormatString,
            ref void* pObject
       );

        [DllImport("rpcrt4.dll")]
        private static unsafe extern void NdrMesTypeFree2(
            IntPtr handle,
            MIDL_TYPE_PICKLING_INFO* pPickingInfo,
            ref MIDL_STUB_DESC pStubDesc,
            IntPtr pFormatString,
            ref IntPtr pObject
       );

        [DllImport("rpcrt4.dll")]
        private static extern int MesHandleFree(IntPtr handle);

        private static readonly ConcurrentDictionary<IntPtr, int> Allocations = new();

        private static IntPtr MIDL_user_allocate(int size)
        {
            var sizePlusPotentialOffset = size + 15;

            var pAllocated = Marshal.AllocHGlobal(sizePlusPotentialOffset);

            GC.AddMemoryPressure(size);

            var pAligned = Align(pAllocated, 8);

            if (pAligned == pAllocated)
            {
                pAligned = IntPtr.Add(pAllocated, 8);
            }

            var offset = (byte)CalculateOffset(pAligned, pAllocated);

            Marshal.WriteByte(pAligned, -1, offset);

            Allocations[pAllocated] = size;

            return pAligned;
        }

        private static void MIDL_user_free(IntPtr f)
        {
            var offset = Marshal.ReadByte(IntPtr.Add(f, -1));

            var pAllocated = IntPtr.Add(f, -offset);

            Marshal.FreeHGlobal(pAllocated);

            if (Allocations.TryRemove(pAllocated, out int allocSize))
            {
                GC.RemoveMemoryPressure(allocSize);
            }
        }

        private static IntPtr CalculateOffset(IntPtr ptr1, IntPtr ptr2)
        {
            if (IntPtr.Size == sizeof(int))
            {
                return new IntPtr(ptr1.ToInt32() - ptr2.ToInt32());
            }

            if (IntPtr.Size == sizeof(long))
            {
                return new IntPtr(ptr1.ToInt64() - ptr2.ToInt64());
            }

            throw new NotSupportedException($"Unknown platform pointer size {IntPtr.Size}");
        }

        private static IntPtr Align(IntPtr ptr, int align)
        {
            align--;

            if (IntPtr.Size == sizeof(int))
            {
                return new IntPtr((ptr.ToInt32() + align) & ~align);
            }

            if (IntPtr.Size == sizeof(long))
            {
                return new IntPtr((ptr.ToInt64() + align) & ~align);
            }

            throw new NotSupportedException($"Unknown platform pointer {IntPtr.Size}");
        }

        public void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    this.pTypeFormatString.Dispose();
                    this.pRpcInterface.Free();
                }

                this.disposed = true;
            }
        }

        ~PickleMarshaller()
        {
            this.Dispose(false);
        }

        public void Dispose()
        {
            this.Dispose(true);

            GC.SuppressFinalize(this);
        }
    }
}