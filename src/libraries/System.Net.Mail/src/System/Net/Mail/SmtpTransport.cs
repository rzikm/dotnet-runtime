// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.IO;
using System.Net.Mime;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Mail
{
    internal sealed class SmtpTransport
    {
        internal const int DefaultPort = 25;

        private readonly ISmtpAuthenticationModule[] _authenticationModules;
        private SmtpConnection? _connection;
        private readonly SmtpClient _client;
        private ICredentialsByHost? _credentials;
        private readonly List<SmtpFailedRecipientException> _failedRecipientExceptions = new List<SmtpFailedRecipientException>();
        private bool _identityRequired;
        private bool _shouldAbort;

        private bool _enableSsl;
        private X509CertificateCollection? _clientCertificates;

        internal SmtpTransport(SmtpClient client) : this(client, SmtpAuthenticationManager.GetModules())
        {
        }

        internal SmtpTransport(SmtpClient client, ISmtpAuthenticationModule[] authenticationModules)
        {
            ArgumentNullException.ThrowIfNull(authenticationModules);

            _client = client;
            _authenticationModules = authenticationModules;
        }

        internal ICredentialsByHost? Credentials
        {
            get
            {
                return _credentials;
            }
            set
            {
                _credentials = value;
            }
        }

        internal bool IdentityRequired
        {
            get
            {
                return _identityRequired;
            }

            set
            {
                _identityRequired = value;
            }
        }

        internal bool IsConnected
        {
            get
            {
                return _connection != null && _connection.IsConnected;
            }
        }

        internal bool EnableSsl
        {
            get
            {
                return _enableSsl;
            }
            set
            {
                _enableSsl = value;
            }
        }

        internal X509CertificateCollection ClientCertificates => _clientCertificates ??= new X509CertificateCollection();

        internal bool ServerSupportsEai
        {
            get { return _connection != null && _connection.ServerSupportsEai; }
        }

        internal void GetConnection(string host, int port)
        {
            try
            {
                lock (this)
                {
                    _connection = new SmtpConnection(this, _client, _credentials, _authenticationModules);
                    if (_shouldAbort)
                    {
                        _connection.Abort();
                    }
                    _shouldAbort = false;
                }

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Associate(this, _connection);

                if (EnableSsl)
                {
                    _connection.EnableSsl = true;
                    _connection.ClientCertificates = ClientCertificates;
                }

                _connection.GetConnection(host, port);
            }
            finally { }
        }

        internal async Task GetConnectionAsync(ContextAwareResult? outerResult, string host, int port, CancellationToken cancellationToken = default)
        {
            try
            {
                lock (this)
                {
                    _connection = new SmtpConnection(this, _client, _credentials, _authenticationModules);
                    if (_shouldAbort)
                    {
                        _connection.Abort();
                    }
                    _shouldAbort = false;
                }

                if (NetEventSource.Log.IsEnabled()) NetEventSource.Associate(this, _connection);

                if (EnableSsl)
                {
                    _connection.EnableSsl = true;
                    _connection.ClientCertificates = ClientCertificates;
                }

                await _connection.GetConnectionAsync(host, port, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception innerException)
            {
                throw new SmtpException(SR.MailHostNotFound, innerException);
            }
        }

        internal async Task<MailWriter> SendMailAsync(MailAddress sender, MailAddressCollection recipients, string deliveryNotify, bool allowUnicode)
        {
            ArgumentNullException.ThrowIfNull(sender);
            ArgumentNullException.ThrowIfNull(recipients);

            MailCommand.Send(_connection!, SmtpCommands.Mail, sender, allowUnicode);
            _failedRecipientExceptions.Clear();

            foreach (MailAddress address in recipients)
            {
                string smtpAddress = address.GetSmtpAddress(allowUnicode);
                string to = smtpAddress + (_connection!.DSNEnabled ? deliveryNotify : string.Empty);
                (bool success, string? response) = await RecipientCommand.SendAsync(_connection, to).ConfigureAwait(false);
                if (!success)
                {
                    _failedRecipientExceptions.Add(
                        new SmtpFailedRecipientException(_connection.Reader!.StatusCode, smtpAddress, response));
                }
            }

            if (_failedRecipientExceptions.Count > 0)
            {
                if (_failedRecipientExceptions.Count == 1)
                {
                    throw _failedRecipientExceptions[0];
                }
                else
                {
                    throw new SmtpFailedRecipientsException(_failedRecipientExceptions, _failedRecipientExceptions.Count == recipients.Count);
                }
            }

            await DataCommand.SendAsync(_connection!).ConfigureAwait(false);
            return new MailWriter(_connection!.GetClosableStream(), encodeForTransport: true);
        }

        internal void ReleaseConnection()
        {
            _connection?.ReleaseConnection();
        }

        internal void Abort()
        {
            lock (this)
            {
                if (_connection != null)
                {
                    _connection.Abort();
                }
                else
                {
                    _shouldAbort = true;
                }
            }
        }

        internal MailWriter SendMail(MailAddress sender, MailAddressCollection recipients, string deliveryNotify,
            bool allowUnicode, out SmtpFailedRecipientException? exception)
        {
            ArgumentNullException.ThrowIfNull(sender);
            ArgumentNullException.ThrowIfNull(recipients);

            MailCommand.Send(_connection!, SmtpCommands.Mail, sender, allowUnicode);
            _failedRecipientExceptions.Clear();

            exception = null;
            string response;
            foreach (MailAddress address in recipients)
            {
                string smtpAddress = address.GetSmtpAddress(allowUnicode);
                string to = smtpAddress + (_connection!.DSNEnabled ? deliveryNotify : string.Empty);
                if (!RecipientCommand.Send(_connection, to, out response))
                {
                    _failedRecipientExceptions.Add(
                        new SmtpFailedRecipientException(_connection.Reader!.StatusCode, smtpAddress, response));
                }
            }

            if (_failedRecipientExceptions.Count > 0)
            {
                if (_failedRecipientExceptions.Count == 1)
                {
                    exception = _failedRecipientExceptions[0];
                }
                else
                {
                    exception = new SmtpFailedRecipientsException(_failedRecipientExceptions, _failedRecipientExceptions.Count == recipients.Count);
                }

                if (_failedRecipientExceptions.Count == recipients.Count)
                {
                    exception.fatal = true;
                    throw exception;
                }
            }

            DataCommand.Send(_connection!);
            return new MailWriter(_connection!.GetClosableStream(), encodeForTransport: true);
        }
    }
}
