// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Text.Json;
using NuGet.Frameworks;

namespace NuGet.ProjectModel
{
    /// <summary>
    /// A <see cref="Utf8JsonStreamReaderConverter{T}"/> to allow read JSON into <see cref="LockFileTarget"/>
    /// </summary>
    internal class Utf8JsonStreamLockFileTargetConverter : IUtf8JsonStreamReaderConverter<LockFileTarget>
    {
        public LockFileTarget Read(ref Utf8JsonStreamReader reader)
        {
            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException("Expected PropertyName, found " + reader.TokenType);
            }

            var lockFileTarget = new LockFileTarget();
            //We want to read the property name right away
            var propertyName = reader.GetString();
            var parts = propertyName.Split(JsonUtility.PathSplitChars, 2);
            lockFileTarget.TargetFramework = NuGetFramework.Parse(parts[0]);
            if (parts.Length == 2)
            {
                lockFileTarget.RuntimeIdentifier = parts[1];
            }

            reader.Read();
            lockFileTarget.Libraries = reader.ReadObjectAsList(Utf8JsonReaderExtensions.LockFileTargetLibraryConverter);

            return lockFileTarget;
        }
    }
}
