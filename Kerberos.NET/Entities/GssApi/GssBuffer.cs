// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities.GssApi
{
    /// <summary>
    /// Represents a GSS-API buffer descriptor.
    /// </summary>
    public class GssBuffer : IDisposable
    {
        private bool disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="GssBuffer"/> class.
        /// </summary>
        public GssBuffer()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GssBuffer"/> class with data.
        /// </summary>
        /// <param name="data">The data to store in the buffer.</param>
        public GssBuffer(ReadOnlyMemory<byte> data)
        {
            this.Data = data;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="GssBuffer"/> class with data.
        /// </summary>
        /// <param name="data">The data to store in the buffer.</param>
        public GssBuffer(byte[] data)
        {
            this.Data = data;
        }

        /// <summary>
        /// Gets or sets the buffer data.
        /// </summary>
        public ReadOnlyMemory<byte> Data { get; set; }

        /// <summary>
        /// Gets the length of the buffer.
        /// </summary>
        public int Length => Data.Length;

        /// <summary>
        /// Gets a value indicating whether the buffer is empty.
        /// </summary>
        public bool IsEmpty => Data.IsEmpty;

        /// <summary>
        /// Converts the buffer to a byte array.
        /// </summary>
        public byte[] ToArray() => Data.ToArray();

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // Clear sensitive data
                    Data = ReadOnlyMemory<byte>.Empty;
                }

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
