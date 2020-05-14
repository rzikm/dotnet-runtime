// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Quic
{

#if WANT_QUIC_PUBLIC
    public
#else
    internal
#endif
    class QuicOperationAbortedException : QuicException
    {
        internal QuicOperationAbortedException()
            : base(SR.net_quic_operationaborted)
        {
        }

        public QuicOperationAbortedException(string message) : base(message)
        {
        }
    }
}
