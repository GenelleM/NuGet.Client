// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.CommandLineUtils;
using NuGet.Configuration;
using NuGet.Credentials;

namespace NuGet.CommandLine.XPlat
{
    internal class PackageSearchCommand
    {
        public static void Register(CommandLineApplication app, Func<ILoggerWithColor> getLogger)
        {
            Register(app, getLogger, SetupSettingsAndRunSearchAsync);
        }

        public static void Register(CommandLineApplication app, Func<ILoggerWithColor> getLogger, Func<PackageSearchArgs, string, Task<int>> setupSettingsAndRunSearchAsync)
        {
            app.Command("search", pkgSearch =>
            {
                pkgSearch.Description = Strings.pkgSearch_Description;
                CommandOption help = pkgSearch.HelpOption(XPlatUtility.HelpOption);
                CommandArgument searchTerm = pkgSearch.Argument(
                    "<Search Term>",
                    Strings.pkgSearch_termDescription);
                CommandOption sources = pkgSearch.Option(
                    "--source",
                    Strings.pkgSearch_SourceDescription,
                    CommandOptionType.MultipleValue);
                CommandOption exactMatch = pkgSearch.Option(
                    "--exact-match",
                    Strings.pkgSearch_ExactMatchDescription,
                    CommandOptionType.NoValue);
                CommandOption format = pkgSearch.Option(
                    "--format",
                    Strings.pkgSearch_FormatDescription,
                    CommandOptionType.SingleValue);
                CommandOption prerelease = pkgSearch.Option(
                    "--prerelease",
                    Strings.pkgSearch_PrereleaseDescription,
                    CommandOptionType.NoValue);
                CommandOption interactive = pkgSearch.Option(
                    "--interactive",
                    Strings.pkgSearch_InteractiveDescription,
                    CommandOptionType.NoValue);
                CommandOption take = pkgSearch.Option(
                    "--take",
                    Strings.pkgSearch_TakeDescription,
                    CommandOptionType.SingleValue);
                CommandOption skip = pkgSearch.Option(
                    "--skip",
                    Strings.pkgSearch_SkipDescription,
                    CommandOptionType.SingleValue);
                CommandOption verbosity = pkgSearch.Option(
                    "--verbosity",
                    Strings.pkgSearch_VerbosityDescription,
                    CommandOptionType.SingleValue);
                CommandOption configFile = pkgSearch.Option(
                    "--configfile",
                    Strings.pkgSearch_ConfigFileDescription,
                    CommandOptionType.SingleValue);

                pkgSearch.OnExecute(async () =>
                {
                    PackageSearchArgs packageSearchArgs;
                    ILoggerWithColor logger = getLogger();
                    try
                    {
                        packageSearchArgs = new PackageSearchArgs(skip.Value(), take.Value(), format.Value(), verbosity.Value())
                        {
                            Sources = sources.Values,
                            SearchTerm = searchTerm.Value,
                            ExactMatch = exactMatch.HasValue(),
                            Interactive = interactive.HasValue(),
                            Prerelease = prerelease.HasValue(),
                            Logger = logger,
                        };
                    }
                    catch (ArgumentException ex)
                    {
                        logger.LogError(ex.Message);
                        return 1;
                    }

                    return await setupSettingsAndRunSearchAsync(packageSearchArgs, configFile.Value());
                });
            });
        }

        public static async Task<int> SetupSettingsAndRunSearchAsync(PackageSearchArgs packageSearchArgs, string configFile)
        {
            DefaultCredentialServiceUtility.SetupDefaultCredentialService(packageSearchArgs.Logger, !packageSearchArgs.Interactive);

            ISettings settings = Settings.LoadDefaultSettings(
                Directory.GetCurrentDirectory(),
                configFileName: configFile,
                machineWideSettings: new XPlatMachineWideSetting());
            PackageSourceProvider sourceProvider = new PackageSourceProvider(settings);

            // If a search lasts more than 15 minutes it is canceled.
            var cts = new CancellationTokenSource(TimeSpan.FromMinutes(15));

            return await PackageSearchRunner.RunAsync(
                sourceProvider,
                packageSearchArgs,
                cts.Token);
        }
    }
}
