// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using NuGet.Frameworks;
using NuGet.LibraryModel;

namespace NuGet.ProjectModel
{
    /// <summary>
    /// A <see cref="IUtf8JsonStreamReaderConverter{T}"/> to allow read JSON into <see cref="LockFile"/>
    /// </summary>
    internal class Utf8JsonStreamLockFileConverter : IUtf8JsonStreamReaderConverter<LockFile>
    {
        private static readonly byte[] VersionPropertyName = Encoding.UTF8.GetBytes("version");
        private static readonly byte[] LibrariesPropertyName = Encoding.UTF8.GetBytes("libraries");
        private static readonly byte[] TargetsPropertyName = Encoding.UTF8.GetBytes("targets");
        private static readonly byte[] ProjectFileDependencyGroupsPropertyName = Encoding.UTF8.GetBytes("projectFileDependencyGroups");
        private static readonly byte[] PackageFoldersPropertyName = Encoding.UTF8.GetBytes("packageFolders");
        private static readonly byte[] ProjectPropertyName = Encoding.UTF8.GetBytes("project");
        private static readonly byte[] CentralTransitiveDependencyGroupsPropertyName = Encoding.UTF8.GetBytes("centralTransitiveDependencyGroups");
        private static readonly byte[] LogsPropertyName = Encoding.UTF8.GetBytes("logs");

        public LockFile Read(ref Utf8JsonStreamReader reader)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException("Expected StartObject, found " + reader.TokenType);
            }

            var lockFile = new LockFile();

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals(VersionPropertyName))
                {
                    reader.Read();
                    if (reader.TryGetInt32(out int version))
                    {
                        lockFile.Version = version;
                    }
                    else
                    {
                        lockFile.Version = int.MinValue;
                    }
                }
                else if (reader.ValueTextEquals(LibrariesPropertyName))
                {
                    reader.Read();
                    lockFile.Libraries = reader.ReadObjectAsList<LockFileLibrary>(Utf8JsonReaderExtensions.LockFileLibraryConverter);
                }
                else if (reader.ValueTextEquals(TargetsPropertyName))
                {
                    reader.Read();
                    lockFile.Targets = reader.ReadObjectAsList<LockFileTarget>(Utf8JsonReaderExtensions.LockFileTargetConverter);
                }
                else if (reader.ValueTextEquals(ProjectFileDependencyGroupsPropertyName))
                {
                    reader.Read();
                    lockFile.ProjectFileDependencyGroups = reader.ReadObjectAsList<ProjectFileDependencyGroup>(Utf8JsonReaderExtensions.ProjectFileDepencencyGroupConverter);
                }
                else if (reader.ValueTextEquals(PackageFoldersPropertyName))
                {
                    reader.Read();
                    lockFile.PackageFolders = reader.ReadObjectAsList<LockFileItem>(Utf8JsonReaderExtensions.LockFileItemConverter);
                }
                else if (reader.ValueTextEquals(ProjectPropertyName))
                {
                    reader.Read();
                    lockFile.PackageSpec = JsonPackageSpecReader.GetPackageSpec(
                        ref reader,
                        name: null,
                        packageSpecPath: null,
                        snapshotValue: null);
                }
                else if (reader.ValueTextEquals(CentralTransitiveDependencyGroupsPropertyName))
                {
                    var results = new List<CentralTransitiveDependencyGroup>();
                    if (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                    {
                        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                        {
                            var frameworkPropertyName = reader.GetString();
                            NuGetFramework framework = NuGetFramework.Parse(frameworkPropertyName);
                            var dependencies = new List<LibraryDependency>();

                            JsonPackageSpecReader.ReadCentralTransitiveDependencyGroup(
                                jsonReader: ref reader,
                                results: dependencies,
                                packageSpecPath: string.Empty);
                            results.Add(new CentralTransitiveDependencyGroup(framework, dependencies));
                        }
                    }
                    lockFile.CentralTransitiveDependencyGroups = results;
                }
                else if (reader.ValueTextEquals(LogsPropertyName))
                {
                    reader.ReadArrayOfObjects<AssetsLogMessage, IAssetsLogMessage>(lockFile.LogMessages, Utf8JsonReaderExtensions.AssetsLogMessageConverter);
                }
                else
                {
                    reader.Skip();
                }
            }

            if (!string.IsNullOrEmpty(lockFile.PackageSpec?.RestoreMetadata?.ProjectPath) && lockFile.LogMessages.Count > 0)
            {
                foreach (AssetsLogMessage message in lockFile.LogMessages.Where(x => string.IsNullOrEmpty(x.ProjectPath)))
                {
                    message.FilePath = lockFile.PackageSpec.RestoreMetadata.ProjectPath;
                }
            }

            return lockFile;
        }
    }
}
