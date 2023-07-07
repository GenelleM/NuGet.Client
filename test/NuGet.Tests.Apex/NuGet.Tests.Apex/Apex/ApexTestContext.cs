// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics;
using System.Threading;
using Microsoft.Test.Apex.VisualStudio;
using Microsoft.Test.Apex.VisualStudio.Solution;
using NuGet.Test.Utility;

namespace NuGet.Tests.Apex
{
    internal class ApexTestContext : IDisposable
    {

        private VisualStudioHost _visualStudio;
        private SimpleTestPathContext _pathContext;

        public SolutionService SolutionService { get; }
        public ProjectTestExtension Project { get; }
        public string PackageSource => _pathContext.PackageSource;
        public string NuGetConfig => _pathContext.NuGetConfig;

        public NuGetApexTestService NuGetApexTestService { get; }

        public ApexTestContext(VisualStudioHost visualStudio, ProjectTemplate projectTemplate, bool noAutoRestore = false, bool addNetStandardFeeds = false, SimpleTestPathContext simpleTestPathContext = null)
        {
            Trace.WriteLine("Creating test context");
            _pathContext = simpleTestPathContext ?? new SimpleTestPathContext();

            if (noAutoRestore)
            {
                _pathContext.Settings.DisableAutoRestore();
            }

            if (addNetStandardFeeds)
            {
                _pathContext.Settings.AddNetStandardFeeds();
            }

            _visualStudio = visualStudio;
            SolutionService = _visualStudio.Get<SolutionService>();
            NuGetApexTestService = _visualStudio.Get<NuGetApexTestService>();

            VisualStudioHostExtension.ClearWindows(_visualStudio);

            Project = CommonUtility.CreateAndInitProject(projectTemplate, _pathContext, SolutionService);

            NuGetApexTestService.WaitForAutoRestore();
        }

        public void Dispose()
        {
            Trace.WriteLine("Test complete, closing solution.");
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    SolutionService.SaveAndClose();
                    break;
                }
                catch (Exception ex)
                {
                    Trace.TraceError($"Failed to close VS on dispose. Attempt #{attempt}");
                    Thread.Sleep(TimeSpan.FromSeconds(3));
                    Trace.TraceError($"{ex.Message}");
                    //ExceptionUtilities.LogException(ex, _logger);
                }
            }
            _pathContext.Dispose();
        }
    }
}
