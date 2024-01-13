// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Core;
using NuGet.Protocol;
using NuGet.Protocol.Model;
using NuGet.Versioning;
using NuGet.Protocol.Core.Types;
using System.Diagnostics;

namespace NuGet.PackageManagement
{
    internal class AuditUtility
    {
        private readonly IEnumerable<PackageRestoreData> _packages;
        private readonly List<SourceRepository> _sourceRepositories;
        private readonly ILogger _logger;
        private readonly SourceCacheContext _sourceCacheContext;
        private readonly PackageVulnerabilitySeverity _minSeverity;

        // if not enabled never call, right? Should we provide that information in the restore information event?
        // Send telemetry similar to the package reference once. where does this get called?
        // Can I use the same `SourceRepository` as the PackageReference projects?
        // What do we need form a configuration perspective?
        // Enabled and then what? Min Severity?
        // Should the nuget.config setting be respected everywhere? 
        public AuditUtility(
            PackageVulnerabilitySeverity minSeverity,
            IEnumerable<PackageRestoreData> packages,
            List<SourceRepository> sourceRepositories,
            SourceCacheContext sourceCacheContext,
            ILogger logger)
        {
            _minSeverity = minSeverity;
            _packages = packages;
            _sourceRepositories = sourceRepositories;
            _sourceCacheContext = sourceCacheContext;
            _logger = logger;
        }

        public async Task CheckPackageVulnerabilitiesAsync(CancellationToken cancellationToken, Dictionary<string, object> metrics)
        {
            metrics["Severity"] = (int)_minSeverity;

            Stopwatch stopwatch = Stopwatch.StartNew();
            GetVulnerabilityInfoResult? allVulnerabilityData = await GetAllVulnerabilityDataAsync(_sourceRepositories, _sourceCacheContext, _logger, metrics, cancellationToken);
            stopwatch.Stop();
            metrics["DownloadDurationSeconds"] = stopwatch.Elapsed.TotalSeconds;

            if (allVulnerabilityData?.Exceptions is not null)
            {
                foreach (Exception exception in allVulnerabilityData.Exceptions.InnerExceptions)
                {
                    var messageText = string.Format(Strings.Error_VulnerabilityDataFetch, exception.Message);
                    var logMessage = RestoreLogMessage.CreateWarning(NuGetLogCode.NU1900, messageText);
                    _logger.Log(logMessage);
                }
            }

            if (allVulnerabilityData is null || !IsAnyVulnerabilityDataFound(allVulnerabilityData.KnownVulnerabilities))
            {
                return;
            }
            stopwatch.Restart();
            Dictionary<PackageIdentity, PackageAuditInfo>? packagesWithKnownVulnerabilities =
                FindPackagesWithKnownVulnerabilities(allVulnerabilityData.KnownVulnerabilities!,
                                                    _packages,
                                                    _minSeverity,
                                                    metrics);
            if (packagesWithKnownVulnerabilities is not null)
            {
                CreateWarningsForPackagesWithVulnerabilities(packagesWithKnownVulnerabilities, _logger);
            }
            stopwatch.Stop();
            metrics["CheckPackagesDurationSeconds"] = stopwatch.Elapsed.TotalSeconds;

            static bool IsAnyVulnerabilityDataFound(IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<PackageVulnerabilityInfo>>>? knownVulnerabilities)
            {
                if (knownVulnerabilities is null || knownVulnerabilities.Count == 0)
                {
                    return false;
                }

                for (var i = 0; i < knownVulnerabilities.Count; i++)
                {
                    if (knownVulnerabilities[i].Count > 0) { return true; }
                }
                return false;
            }
        }

        internal static async Task<GetVulnerabilityInfoResult?> GetAllVulnerabilityDataAsync(List<SourceRepository> sourceRepositories, SourceCacheContext sourceCacheContext, ILogger logger, Dictionary<string, object> metrics, CancellationToken cancellationToken)
        {
            int SourcesWithVulnerabilityData = 0;
            List<Task<GetVulnerabilityInfoResult?>>? results = new(sourceRepositories.Count);

            foreach (SourceRepository source in sourceRepositories)
            {
                Task<GetVulnerabilityInfoResult?> getVulnerabilityInfoResult = GetVulnerabilityInfoAsync(source, sourceCacheContext, logger);
                if (getVulnerabilityInfoResult != null)
                {
                    results.Add(getVulnerabilityInfoResult);
                }
            }

            await Task.WhenAll(results);
            if (cancellationToken.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
            }

            List<Exception>? errors = null;
            List<IReadOnlyDictionary<string, IReadOnlyList<PackageVulnerabilityInfo>>>? knownVulnerabilities = null;
            foreach (var resultTask in results)
            {
                GetVulnerabilityInfoResult? result = await resultTask;
                if (result is null) continue;

                if (result.KnownVulnerabilities != null)
                {
                    SourcesWithVulnerabilityData++;
                    knownVulnerabilities ??= new();

                    knownVulnerabilities.AddRange(result.KnownVulnerabilities);
                }

                if (result.Exceptions != null)
                {
                    errors ??= new();

                    errors.AddRange(result.Exceptions.InnerExceptions);
                }
            }

            metrics[nameof(SourcesWithVulnerabilityData)] = SourcesWithVulnerabilityData;

            GetVulnerabilityInfoResult? final =
                knownVulnerabilities != null || errors != null
                ? new(knownVulnerabilities, errors != null ? new AggregateException(errors) : null)
                : null;
            return final;

            static async Task<GetVulnerabilityInfoResult?> GetVulnerabilityInfoAsync(SourceRepository source, SourceCacheContext cacheContext, ILogger logger)
            {
                IVulnerabilityInfoResource vulnerabilityInfoResource =
                    await source.GetResourceAsync<IVulnerabilityInfoResource>(CancellationToken.None);
                if (vulnerabilityInfoResource is null)
                {
                    return null;
                }
                return await vulnerabilityInfoResource.GetVulnerabilityInfoAsync(cacheContext, logger, CancellationToken.None);
            }
        }

        internal static void CreateWarningsForPackagesWithVulnerabilities(Dictionary<PackageIdentity, PackageAuditInfo> packagesWithKnownVulnerabilities, ILogger logger)
        {
            foreach ((PackageIdentity package, PackageAuditInfo auditInfo) in packagesWithKnownVulnerabilities.OrderBy(p => p.Key.Id))
            {
                foreach (PackageVulnerabilityInfo vulnerability in auditInfo.Vulnerabilities)
                {
                    (var severityLabel, NuGetLogCode logCode) = GetSeverityLabelAndCode(vulnerability.Severity);
                    var message = string.Format(Strings.Warning_PackageWithKnownVulnerability,
                        package.Id,
                        package.Version.ToNormalizedString(),
                        severityLabel,
                        vulnerability.Url);
                    var restoreLogMessage =
                        RestoreLogMessage.CreateWarning(logCode,
                        message,
                        package.Id);
                    logger.Log(restoreLogMessage);
                }
            }
        }

        internal static Dictionary<PackageIdentity, PackageAuditInfo>? FindPackagesWithKnownVulnerabilities(
            IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<PackageVulnerabilityInfo>>> knownVulnerabilities,
            IEnumerable<PackageRestoreData> packages, PackageVulnerabilitySeverity minSeverity, Dictionary<string, object> metrics)
        {
            Dictionary<PackageIdentity, PackageAuditInfo>? result = null;

            int Sev0Matches = 0;
            int Sev1Matches = 0;
            int Sev2Matches = 0;
            int Sev3Matches = 0;
            int InvalidSevMatches = 0;

            foreach (PackageRestoreData packageRestoreData in packages)
            {
                PackageIdentity packageIdentity = packageRestoreData.PackageReference.PackageIdentity;
                List<PackageVulnerabilityInfo>? knownVulnerabilitiesForPackage = GetKnownVulnerabilities(packageIdentity.Id, packageIdentity.Version, knownVulnerabilities);

                if (knownVulnerabilitiesForPackage?.Count > 0)
                {
                    foreach (PackageVulnerabilityInfo knownVulnerability in knownVulnerabilitiesForPackage)
                    {
                        if ((int)knownVulnerability.Severity < (int)minSeverity && knownVulnerability.Severity != PackageVulnerabilitySeverity.Unknown) 
                        {
                            continue;
                        }

                        PackageVulnerabilitySeverity severity = knownVulnerability.Severity;
                        if (severity == PackageVulnerabilitySeverity.Low) { Sev0Matches++; }
                        else if (severity == PackageVulnerabilitySeverity.Moderate) { Sev1Matches++; }
                        else if (severity == PackageVulnerabilitySeverity.High) { Sev2Matches++; }
                        else if (severity == PackageVulnerabilitySeverity.Critical) { Sev3Matches++; }
                        else { InvalidSevMatches++; }

                        result ??= new();

                        if (!result.TryGetValue(packageIdentity, out PackageAuditInfo? auditInfo))
                        {
                            auditInfo = new(packageIdentity);
                            result.Add(packageIdentity, auditInfo);
                        }

                        auditInfo.Vulnerabilities.Add(knownVulnerability);
                    }
                }
            }
            var PackagesWithAdvisory = result?.Keys?.Select(e => e.Id).ToList();
            metrics[nameof(Sev0Matches)] = Sev0Matches;
            metrics[nameof(Sev1Matches)] = Sev1Matches;
            metrics[nameof(Sev2Matches)] = Sev2Matches;
            metrics[nameof(Sev3Matches)] = Sev3Matches;
            metrics[nameof(InvalidSevMatches)] = InvalidSevMatches; // TODO NK - Is this a thing?
            // TODO NK - Add packages severity with PII?

            return result;
        }

        internal static List<PackageVulnerabilityInfo>? GetKnownVulnerabilities(
            string name,
            NuGetVersion version,
            IReadOnlyList<IReadOnlyDictionary<string, IReadOnlyList<PackageVulnerabilityInfo>>> knownVulnerabilities)
        {
            HashSet<PackageVulnerabilityInfo>? vulnerabilities = null;

            foreach (var file in knownVulnerabilities)
            {
                if (file.TryGetValue(name, out var packageVulnerabilities))
                {
                    foreach (var vulnerabilityInfo in packageVulnerabilities)
                    {
                        if (vulnerabilityInfo.Versions.Satisfies(version))
                        {
                            vulnerabilities ??= new();
                            vulnerabilities.Add(vulnerabilityInfo);
                        }
                    }
                }
            }

            return vulnerabilities?.ToList();
        }

        internal static (string severityLabel, NuGetLogCode code) GetSeverityLabelAndCode(PackageVulnerabilitySeverity severity)
        {
            switch (severity)
            {
                case PackageVulnerabilitySeverity.Low:
                    return ("low", NuGetLogCode.NU1901);
                case PackageVulnerabilitySeverity.Moderate:
                    return ("moderate", NuGetLogCode.NU1902);
                case PackageVulnerabilitySeverity.High:
                    return ("high", NuGetLogCode.NU1903);
                case PackageVulnerabilitySeverity.Critical:
                    return ("critical", NuGetLogCode.NU1904);
                default:
                    return ("unknown", NuGetLogCode.NU1900);
            }
        }

        internal class PackageAuditInfo
        {
            public PackageIdentity Identity { get; }
            public List<PackageVulnerabilityInfo> Vulnerabilities { get; }

            public PackageAuditInfo(PackageIdentity identity)
            {
                Identity = identity;
                Vulnerabilities = new();
            }
        }
    }
}
