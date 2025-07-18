// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates.Asn1;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal static class OpenSslCrlCache
    {
        private static readonly string s_crlDir =
            PersistedFiles.GetUserFeatureDirectory(
                X509Persistence.CryptographyFeatureName,
                X509Persistence.CrlsSubFeatureName);

        private static readonly string s_ocspDir =
            PersistedFiles.GetUserFeatureDirectory(
                X509Persistence.CryptographyFeatureName,
                X509Persistence.OcspSubFeatureName);

        private const ulong X509_R_CERT_ALREADY_IN_HASH_TABLE = 0x0B07D065;

        public static void AddCrlForCertificate(
            SafeX509Handle cert,
            SafeX509StoreHandle store,
            X509RevocationMode revocationMode,
            DateTime verificationTime,
            TimeSpan downloadTimeout)
        {
            // Occasionally clean up stale entries
            if (CacheEnabled && s_cachedCrls.Count > 100 && Random.Shared.Next(100) == 0)
            {
                CleanupCache();
            }

            // In Offline mode, accept any cached CRL we have.
            // "CRL is Expired" is a better match for Offline than "Could not find CRL"
            if (revocationMode != X509RevocationMode.Online)
            {
                verificationTime = DateTime.MinValue;
            }

            string? url = GetCdpUrl(cert);

            if (url == null)
            {
                return;
            }

            string crlFileName = GetCrlFileName(cert, url);

            if (OpenSslX509ChainEventSource.Log.IsEnabled())
            {
                OpenSslX509ChainEventSource.Log.CrlIdentifiersDetermined(cert, url, crlFileName);
            }

            if (AddCachedCrl(crlFileName, store, verificationTime))
            {
                return;
            }

            // Don't do any work if we're prohibited from fetching new CRLs
            if (revocationMode != X509RevocationMode.Online)
            {
                if (OpenSslX509ChainEventSource.Log.IsEnabled())
                {
                    OpenSslX509ChainEventSource.Log.CrlCheckOffline();
                }

                return;
            }

            DownloadAndAddCrl(url, crlFileName, store, downloadTimeout);
        }

        private static bool AddCachedCrl(string crlFileName, SafeX509StoreHandle store, DateTime verificationTime)
        {
            string crlFile = GetCachedCrlPath(crlFileName);

            if (OpenSslX509ChainEventSource.Log.IsEnabled())
            {
                OpenSslX509ChainEventSource.Log.CrlCacheCheckStart();
            }

            try
            {
                return AddCachedCrlCore(crlFile, store, verificationTime);
            }
            finally
            {
                if (OpenSslX509ChainEventSource.Log.IsEnabled())
                {
                    OpenSslX509ChainEventSource.Log.CrlCacheCheckStop();
                }
            }
        }

        private sealed class CacheEntry
        {
            // discriminated union of
            //     Task<SafeX509CrlHandle?> for in-progress downloads/loads
            //     WeakReference<SafeX509CrlHandle> for completed downloads/loads
            public required object Data;
        }

        private static readonly ConcurrentDictionary<string, CacheEntry> s_cachedCrls = new();

        private static bool CacheEnabled = AppContext.TryGetSwitch("System.Security.Cryptography.X509Certificates.EnableInMemCrlCache", out var enabled) ? enabled : false;

        private static SafeX509CrlHandle? GetOrCreateCachedCrl(
            string cacheKey,
            Func<string, SafeX509CrlHandle?> crlFactory)
        {
            if (!CacheEnabled)
            {
                return crlFactory(cacheKey);
            }

            SafeX509CrlHandle? crl = null;

            if (!s_cachedCrls.TryGetValue(cacheKey, out CacheEntry? existingEntry))
            {
                System.Console.WriteLine("No Entry in cache, creating new entry");
                TaskCompletionSource<SafeX509CrlHandle?> tcs = new();
                CacheEntry entry = new CacheEntry { Data = tcs.Task };

                existingEntry = s_cachedCrls.GetOrAdd(cacheKey, entry);

                if (existingEntry == entry)
                {
                    System.Console.WriteLine("Added new entry to cache, parsing");
                    // we succeeded in adding a new entry, we are responsible for completion of the task
                    try
                    {
                        crl = crlFactory(cacheKey);

                        System.Console.WriteLine($"CRL for {cacheKey} parsed successfully: {!crl?.IsInvalid}");
                        if (crl != null && !crl.IsInvalid)
                        {
                            // If we got a valid CRL, store it as a WeakReference for future callers
                            entry.Data = new WeakReference<SafeX509CrlHandle>(crl);
                            // entry.Data = crl;
                        }

                        tcs.SetResult(crl);
                    }
                    catch (Exception ex)
                    {
                        tcs.SetException(ex);
                    }
                }
                else
                {
                    System.Console.WriteLine("Too slow in adding cache entry, using existing entry");
                }
            }

            if (existingEntry.Data is Task<SafeX509CrlHandle?> task)
            {
                // If the existing entry is a Task, wait for it to complete
                crl = task.GetAwaiter().GetResult();
            }
            else if (existingEntry.Data is WeakReference<SafeX509CrlHandle> weakRef)
            {
                if (weakRef.TryGetTarget(out SafeX509CrlHandle? cachedCrl))
                {
                    // If the existing entry is a WeakReference, try to get the target
                    crl = cachedCrl;
                }
                else
                {
                    lock (weakRef)
                    {
                        if (!weakRef.TryGetTarget(out crl))
                        {
                            System.Console.WriteLine($"Restoring dead weakreference for {cacheKey}");
                            // If the weak reference is dead, we need to re-create it
                            crl = crlFactory(cacheKey);
                            if (crl != null && !crl.IsInvalid)
                            {
                                weakRef.SetTarget(crl);
                            }
                        }
                    }
                }
            }
            // TODO: remove this branch, used for testing
            else if (existingEntry.Data is SafeX509CrlHandle existingCrl)
            {
                // If the existing entry is a SafeX509CrlHandle, use it directly
                crl = existingCrl;
            }
            else
            {
                throw new InvalidOperationException("Unexpected cache entry type");
            }

            if (crl is null || crl.IsInvalid)
            {
                //Debug.Fail($"CRL for {cacheKey} is null or invalid, this should not happen if the factory is correct");
                return null;
            }

            return Interop.Crypto.X509CrlUpRef(crl.DangerousGetHandle());
        }

        private static bool AddCachedCrlCore(string crlFile, SafeX509StoreHandle store, DateTime verificationTime)
        {
            SafeX509CrlHandle? crl = GetOrCreateCachedCrl(
                crlFile,
                crlFile =>
                {
                    using (SafeBioHandle bio = Interop.Crypto.BioNewFile(crlFile, "rb"))
                    {
                        if (bio.IsInvalid)
                        {
                            if (OpenSslX509ChainEventSource.Log.IsEnabled())
                            {
                                OpenSslX509ChainEventSource.Log.CrlCacheOpenError();
                            }

                            Interop.Crypto.ErrClearError();
                            return null;
                        }

                        SafeX509CrlHandle crl = Interop.Crypto.PemReadBioX509Crl(bio);

                        if (crl.IsInvalid)
                        {
                            if (OpenSslX509ChainEventSource.Log.IsEnabled())
                            {
                                OpenSslX509ChainEventSource.Log.CrlCacheDecodeError();
                            }

                            Interop.Crypto.ErrClearError();
                            crl.Dispose();
                            return null;
                        }

                        return crl;
                    }
                });

            try
            {
                if (crl is null || crl.IsInvalid)
                {
                    System.Console.WriteLine($"CRL for {crlFile} is null or invalid, this should not happen if the factory is correct");
                    return false;
                }

                // If crl.LastUpdate is in the past, downloading a new version isn't really going
                // to help, since we can't rewind the Internet. So this is just going to fail, but
                // at least it can fail without using the network.
                //
                // If crl.NextUpdate is in the past, try downloading a newer version.
                IntPtr nextUpdatePtr = Interop.Crypto.GetX509CrlNextUpdate(crl);
                DateTime nextUpdate;

                // If there is no crl.NextUpdate, this indicates that the CA is not providing
                // any more updates to the CRL, or they made a mistake not providing a NextUpdate.
                // We'll cache it for a few days to cover the case it was a mistake.
                if (nextUpdatePtr == IntPtr.Zero)
                {
                    if (OpenSslX509ChainEventSource.Log.IsEnabled())
                    {
                        OpenSslX509ChainEventSource.Log.CrlCacheFileBasedExpiry();
                    }

                    try
                    {
                        nextUpdate = File.GetLastWriteTime(crlFile).AddDays(3);
                    }
                    catch
                    {
                        // We couldn't determine when the CRL was last written to,
                        // so consider it expired.
                        Debug.Fail("Failed to get the last write time of the CRL file");
                        return false;
                    }
                }
                else
                {
                    nextUpdate = OpenSslX509CertificateReader.ExtractValidityDateTime(nextUpdatePtr);
                }

                // OpenSSL is going to convert our input time to universal, so we should be in Local or
                // Unspecified (local-assumed).
                Debug.Assert(
                    verificationTime.Kind != DateTimeKind.Utc,
                    "UTC verificationTime should have been normalized to Local");

                // In the event that we're to-the-second accurate on the match, OpenSSL will consider this
                // to be already expired.
                if (nextUpdate <= verificationTime)
                {
                    if (OpenSslX509ChainEventSource.Log.IsEnabled())
                    {
                        OpenSslX509ChainEventSource.Log.CrlCacheExpired(verificationTime, nextUpdate);
                    }

                    System.Console.WriteLine($"CRL for {crlFile} is expired, nextUpdate: {nextUpdate}, verificationTime: {verificationTime}");
                    return false;
                }

                if (!Interop.Crypto.X509StoreAddCrl(store, crl))
                {
                    // Ignore error "cert already in store", throw on anything else. In any case the error queue will be cleared.
                    if (X509_R_CERT_ALREADY_IN_HASH_TABLE == Interop.Crypto.ErrPeekLastError())
                    {
                        Interop.Crypto.ErrClearError();
                    }
                    else
                    {
                        throw Interop.Crypto.CreateOpenSslCryptographicException();
                    }
                }

                if (OpenSslX509ChainEventSource.Log.IsEnabled())
                {
                    OpenSslX509ChainEventSource.Log.CrlCacheAcceptedFile(nextUpdate);
                }

                return true;
            }
            finally
            {
                crl?.Dispose();
            }
        }

        private static void DownloadAndAddCrl(
            string url,
            string crlFileName,
            SafeX509StoreHandle store,
            TimeSpan downloadTimeout)
        {
            SafeX509CrlHandle? crl = OpenSslCertificateAssetDownloader.DownloadCrl(url, downloadTimeout);
            bool shouldDisposeCrl = true;
            try
            {
                // null is a valid return (e.g. no remainingDownloadTime)
                if (crl != null && !crl.IsInvalid)
                {
                    if (!Interop.Crypto.X509StoreAddCrl(store, crl))
                    {
                        // Ignore error "cert already in store", throw on anything else. In any case the error queue will be cleared.
                        if (X509_R_CERT_ALREADY_IN_HASH_TABLE == Interop.Crypto.ErrPeekLastError())
                        {
                            Interop.Crypto.ErrClearError();
                        }
                        else
                        {
                            throw Interop.Crypto.CreateOpenSslCryptographicException();
                        }
                    }

                    // we now have the most up-to-date CRL, update the in-memory cache
                    if (CacheEnabled)
                    {
                        System.Console.WriteLine($"Downloaded CRL for {GetCachedCrlPath(crlFileName)} put in cache");
                        // s_cachedCrls[crlFileName] = new CacheEntry { Data = new WeakReference<SafeX509CrlHandle>(crl) };
                        // replace the entry in the cache

                        string cacheKey = GetCachedCrlPath(crlFileName);

                        if (s_cachedCrls.TryGetValue(cacheKey, out CacheEntry? existingEntry))
                        {
                            lock (existingEntry)
                            {
                                if (existingEntry.Data is Task<SafeX509CrlHandle?> task)
                                {
                                    // If the existing entry is a Task, complete it with the new CRL
                                    task.GetAwaiter().GetResult();
                                    existingEntry.Data = new WeakReference<SafeX509CrlHandle>(crl);
                                    // existingEntry.Data = crl;
                                }
                                else if (existingEntry.Data is WeakReference<SafeX509CrlHandle> weakRef)
                                {
                                    lock (weakRef)
                                    {
                                        if (weakRef.TryGetTarget(out SafeX509CrlHandle? oldCrl))
                                        {
                                            oldCrl?.Dispose();
                                        }

                                        weakRef.SetTarget(crl);
                                    }
                                }
                                else
                                {
                                    // If the existing entry is a SafeX509CrlHandle, replace it
                                    SafeX509CrlHandle? handle = Interlocked.Exchange(ref existingEntry.Data, crl) as SafeX509CrlHandle;
                                    handle?.Dispose();
                                }
                            }
                        }
                        else
                        {
                            s_cachedCrls[GetCachedCrlPath(crlFileName)] = new CacheEntry { Data = crl };
                        }

                        shouldDisposeCrl = false; // don't dispose, cache retains the handle
                    }

                    // Saving the CRL to the disk is just a performance optimization for later requests to not
                    // need to use the network again, so failure to save shouldn't throw an exception or mark
                    // the chain as invalid.
                    try
                    {
                        string crlFile = GetCachedCrlPath(crlFileName, mkDir: true);

                        using (SafeBioHandle bio = Interop.Crypto.BioNewFile(crlFile, "wb"))
                        {
                            if (bio.IsInvalid || Interop.Crypto.PemWriteBioX509Crl(bio, crl) == 0)
                            {
                                // No bio, or write failed

                                if (OpenSslX509ChainEventSource.Log.IsEnabled())
                                {
                                    OpenSslX509ChainEventSource.Log.CrlCacheWriteFailed(crlFile);
                                }

                                Interop.Crypto.ErrClearError();
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    if (OpenSslX509ChainEventSource.Log.IsEnabled())
                    {
                        OpenSslX509ChainEventSource.Log.CrlCacheWriteSucceeded();
                    }
                }
            }
            finally
            {
                if (shouldDisposeCrl)
                {
                    crl?.Dispose();
                }
            }
        }

        private static void CleanupCache()
        {
            if (!CacheEnabled || s_cachedCrls.IsEmpty)
            {
                return;
            }

            // Clean up any entries with dead weak references
            foreach (var key in s_cachedCrls.Keys)
            {
                if (s_cachedCrls.TryGetValue(key, out CacheEntry? entry))
                {
                    if (entry.Data is WeakReference<SafeX509CrlHandle> weakRef && !weakRef.TryGetTarget(out _))
                    {
                        // If we can remove this entry, great
                        s_cachedCrls.TryRemove(key, out _);
                    }
                }
            }
        }

        internal static string GetCachedOcspResponseDirectory()
        {
            return s_ocspDir;
        }

        private static string GetCrlFileName(SafeX509Handle cert, string crlUrl)
        {
            // X509_issuer_name_hash returns "unsigned long", which is marshalled as ulong.
            // But it only sets 32 bits worth of data, so force it down to uint just... in case.
            ulong persistentHashLong = Interop.Crypto.X509IssuerNameHash(cert);
            if (persistentHashLong == 0)
            {
                Interop.Crypto.ErrClearError();
            }

            uint persistentHash = unchecked((uint)persistentHashLong);
            Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];

            // Endianness isn't important, it just needs to be consistent.
            // (Even if the same storage was used for two different endianness systems it'd stabilize at two files).
            ReadOnlySpan<byte> utf16Url = MemoryMarshal.AsBytes(crlUrl.AsSpan());

            if (SHA256.HashData(utf16Url, hash) != hash.Length)
            {
                Debug.Fail("HashData failed or produced an incorrect length output");
                throw new CryptographicException();
            }

            uint urlHash = MemoryMarshal.Read<uint>(hash);

            // OpenSSL's hashed filename algorithm is the 8-character hex version of the 32-bit value
            // of X509_issuer_name_hash (or X509_subject_name_hash, depending on the context).
            //
            // We mix in an 8-character hex version of the "left"-most bytes of a hash of the URL to
            // disambiguate when one Issuing Authority separates their revocation across independent CRLs.
            return $"{persistentHash:x8}.{urlHash:x8}.crl";
        }

        private static string GetCachedCrlPath(string localFileName, bool mkDir = false)
        {
            if (mkDir)
            {
                Directory.CreateDirectory(s_crlDir);
            }

            return Path.Combine(s_crlDir, localFileName);
        }

        private static string? GetCdpUrl(SafeX509Handle cert)
        {
            ArraySegment<byte> crlDistributionPoints =
                OpenSslX509CertificateReader.FindFirstExtension(cert, Oids.CrlDistributionPoints);

            if (crlDistributionPoints.Array == null)
            {
                if (OpenSslX509ChainEventSource.Log.IsEnabled())
                {
                    OpenSslX509ChainEventSource.Log.NoCdpFound(cert);
                }

                return null;
            }

            try
            {
                AsnValueReader reader = new AsnValueReader(crlDistributionPoints, AsnEncodingRules.DER);
                AsnValueReader sequenceReader = reader.ReadSequence();
                reader.ThrowIfNotEmpty();

                while (sequenceReader.HasData)
                {
                    DistributionPointAsn.Decode(ref sequenceReader, crlDistributionPoints, out DistributionPointAsn distributionPoint);

                    // Only distributionPoint is supported
                    // Only fullName is supported, nameRelativeToCRLIssuer is for LDAP-based lookup.
                    if (distributionPoint.DistributionPoint.HasValue &&
                        distributionPoint.DistributionPoint.Value.FullName != null)
                    {
                        foreach (GeneralNameAsn name in distributionPoint.DistributionPoint.Value.FullName)
                        {
                            if (name.Uri != null)
                            {
                                if (Uri.TryCreate(name.Uri, UriKind.Absolute, out Uri? uri) &&
                                    uri.Scheme == "http")
                                {
                                    return name.Uri;
                                }
                                else
                                {
                                    if (OpenSslX509ChainEventSource.Log.IsEnabled())
                                    {
                                        OpenSslX509ChainEventSource.Log.NonHttpCdpEntry(name.Uri);
                                    }
                                }
                            }
                        }

                        if (OpenSslX509ChainEventSource.Log.IsEnabled())
                        {
                            OpenSslX509ChainEventSource.Log.NoMatchingCdpEntry();
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                // Treat any ASN errors as if the extension was missing.
            }
            catch (AsnContentException)
            {
                // Treat any ASN errors as if the extension was missing.
            }
            finally
            {
                // The data came from a certificate, so it's public.
                CryptoPool.Return(crlDistributionPoints.Array, clearSize: 0);
            }

            return null;
        }
    }
}
