// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Threading.Tasks;

namespace System.Net.Mail
{
    //streams are read only; return of 0 means end of server's reply
    internal sealed class SmtpReplyReader : IDisposable
    {
        public void Dispose()
        {
            Close();
        }

        private readonly SmtpReplyReaderFactory _reader;

        internal SmtpReplyReader(SmtpReplyReaderFactory reader)
        {
            _reader = reader;
        }

        internal IAsyncResult BeginReadLines(AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(ReadLinesAsync(), callback, state);
        }

        internal IAsyncResult BeginReadLine(AsyncCallback? callback, object? state)
        {
            return TaskToAsyncResult.Begin(ReadLineAsync(), callback, state);
        }

        public void Close()
        {
            _reader.Close(this);
        }

        internal static LineInfo[] EndReadLines(IAsyncResult result)
        {
            return TaskToAsyncResult.End<LineInfo[]>(result);
        }

        internal static LineInfo EndReadLine(IAsyncResult result)
        {
            return TaskToAsyncResult.End<LineInfo>(result);
        }

        internal LineInfo[] ReadLines()
        {
            return _reader.ReadLines(this);
        }

        internal LineInfo ReadLine()
        {
            return _reader.ReadLine(this);
        }

        internal Task<LineInfo[]> ReadLinesAsync()
        {
            return _reader.ReadLinesAsync(this);
        }

        internal Task<LineInfo> ReadLineAsync()
        {
            return _reader.ReadLineAsync(this);
        }
    }
}
