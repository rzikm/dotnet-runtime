// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Net.Mime;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Mail
{
    internal static class CheckCommand
    {
        internal static async Task<LineInfo> SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            await conn.FlushAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
            using SmtpReplyReader reader = conn.Reader!.GetNextReplyReader();
            return await reader.ReadLineAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
        }
    }

    internal static class ReadLinesCommand
    {
        internal static async Task<LineInfo[]> SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            await conn.FlushAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
            return await conn.Reader!.GetNextReplyReader().ReadLinesAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
        }
    }

    internal static class AuthCommand
    {
        internal static async Task<LineInfo> SendAsync<TIOAdapter>(SmtpConnection conn, string type, string message, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, type, message);
            LineInfo[] lines = await ReadLinesCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        internal static async Task<LineInfo> SendAsync<TIOAdapter>(SmtpConnection conn, string? message, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, message);
            LineInfo[] lines = await ReadLinesCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        private static LineInfo CheckResponse(LineInfo[] lines)
        {
            if (lines == null || lines.Length == 0)
            {
                throw new SmtpException(SR.SmtpAuthResponseInvalid);
            }
            System.Diagnostics.Debug.Assert(lines.Length == 1, "Did not expect more than one line response for auth command");
            return lines[0];
        }

        private static void PrepareCommand(SmtpConnection conn, string type, string message)
        {
            conn.BufferBuilder.Append(SmtpCommands.Auth.Span);
            conn.BufferBuilder.Append(type);
            conn.BufferBuilder.Append((byte)' ');
            conn.BufferBuilder.Append(message);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }

        private static void PrepareCommand(SmtpConnection conn, string? message)
        {
            conn.BufferBuilder.Append(message);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class DataCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.StartMailInput:
                    {
                        return;
                    }
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.TransactionFailed:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Data);
        }
    }

    internal static class DataStopCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.TransactionFailed:
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.InsufficientStorage:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.DataStop);
        }
    }

    internal static class EHelloCommand
    {
        internal static async Task<string[]> SendAsync<TIOAdapter>(SmtpConnection conn, string domain, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, domain);
            LineInfo[] lines = await ReadLinesCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            return CheckResponse(lines);
        }

        private static string[] CheckResponse(LineInfo[] lines)
        {
            if (lines == null || lines.Length == 0)
            {
                throw new SmtpException(SR.SmtpEhloResponseInvalid);
            }
            if (lines[0].StatusCode != SmtpStatusCode.Ok)
            {
                if ((int)lines[0].StatusCode < 400)
                {
                    throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, lines[0].Line);
                }

                throw new SmtpException(lines[0].StatusCode, lines[0].Line, true);
            }
            string[] extensions = new string[lines.Length - 1];
            for (int i = 1; i < lines.Length; i++)
            {
                extensions[i - 1] = lines[i].Line;
            }
            return extensions;
        }

        private static void PrepareCommand(SmtpConnection conn, string domain)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.EHello);
            conn.BufferBuilder.Append(domain);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class HelloCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, string domain, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, domain);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string serverResponse)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, serverResponse);
                        }

                        throw new SmtpException(statusCode, serverResponse, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, string domain)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Hello);
            conn.BufferBuilder.Append(domain);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class StartTlsCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.ServiceReady:
                    {
                        return;
                    }

                case SmtpStatusCode.ClientNotPermitted:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.StartTls);
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class MailCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, command, from, allowUnicode);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            CheckResponse(info.StatusCode, info.Line);
        }

        private static void CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                    {
                        return;
                    }
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.LocalErrorInProcessing:
                case SmtpStatusCode.InsufficientStorage:
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, ReadOnlyMemory<byte> command, MailAddress from, bool allowUnicode)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }
            conn.BufferBuilder.Append(command);
            string fromString = from.GetSmtpAddress(allowUnicode);
            conn.BufferBuilder.Append(fromString, allowUnicode);
            if (allowUnicode)
            {
                conn.BufferBuilder.Append(" BODY=8BITMIME SMTPUTF8");
            }
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class RecipientCommand
    {
        internal static async Task<(bool success, string response)> SendAsync<TIOAdapter>(SmtpConnection conn, string to, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn, to);
            LineInfo info = await CheckCommand.SendAsync<TIOAdapter>(conn, cancellationToken).ConfigureAwait(false);
            return (CheckResponse(info.StatusCode, info.Line), info.Line);
        }

        private static bool CheckResponse(SmtpStatusCode statusCode, string response)
        {
            switch (statusCode)
            {
                case SmtpStatusCode.Ok:
                case SmtpStatusCode.UserNotLocalWillForward:
                    {
                        return true;
                    }
                case SmtpStatusCode.MailboxUnavailable:
                case SmtpStatusCode.UserNotLocalTryAlternatePath:
                case SmtpStatusCode.ExceededStorageAllocation:
                case SmtpStatusCode.MailboxNameNotAllowed:
                case SmtpStatusCode.MailboxBusy:
                case SmtpStatusCode.InsufficientStorage:
                    {
                        return false;
                    }
                default:
                    {
                        if ((int)statusCode < 400)
                        {
                            throw new SmtpException(SR.net_webstatus_ServerProtocolViolation, response);
                        }

                        throw new SmtpException(statusCode, response, true);
                    }
            }
        }

        private static void PrepareCommand(SmtpConnection conn, string to)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Recipient);
            conn.BufferBuilder.Append(to, true); // Unicode validation was done prior
            conn.BufferBuilder.Append(SmtpCommands.CRLF);
        }
    }

    internal static class QuitCommand
    {
        internal static async Task SendAsync<TIOAdapter>(SmtpConnection conn, CancellationToken cancellationToken = default)
            where TIOAdapter : IReadWriteAdapter
        {
            PrepareCommand(conn);
            await conn.FlushAsync<TIOAdapter>(cancellationToken).ConfigureAwait(false);
            // We don't read any response to match the synchronous behavior
        }

        private static void PrepareCommand(SmtpConnection conn)
        {
            if (conn.IsStreamOpen)
            {
                throw new InvalidOperationException(SR.SmtpDataStreamOpen);
            }

            conn.BufferBuilder.Append(SmtpCommands.Quit);
        }
    }

    internal static class SmtpCommands
    {
        internal static ReadOnlyMemory<byte> Auth => "AUTH "u8.ToArray();
        internal static ReadOnlyMemory<byte> CRLF => "\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Data => "DATA\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> DataStop => "\r\n.\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> EHello => "EHLO "u8.ToArray();
        internal static ReadOnlyMemory<byte> Expand => "EXPN "u8.ToArray();
        internal static ReadOnlyMemory<byte> Hello => "HELO "u8.ToArray();
        internal static ReadOnlyMemory<byte> Help => "HELP"u8.ToArray();
        internal static ReadOnlyMemory<byte> Mail => "MAIL FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Noop => "NOOP\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Quit => "QUIT\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Recipient => "RCPT TO:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Reset => "RSET\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Send => "SEND FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> SendAndMail => "SAML FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> SendOrMail => "SOML FROM:"u8.ToArray();
        internal static ReadOnlyMemory<byte> Turn => "TURN\r\n"u8.ToArray();
        internal static ReadOnlyMemory<byte> Verify => "VRFY "u8.ToArray();
        internal static ReadOnlyMemory<byte> StartTls => "STARTTLS"u8.ToArray();
    }

    internal readonly struct LineInfo
    {
        internal LineInfo(SmtpStatusCode statusCode, string line)
        {
            StatusCode = statusCode;
            Line = line;
        }
        internal string Line { get; }
        internal SmtpStatusCode StatusCode { get; }
    }
}
