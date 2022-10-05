// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Build", "CA1303:Method 'AssetTargetFallbackFramework.AssetTargetFallbackFramework(NuGetFramework framework, IList<NuGetFramework> fallbackFrameworks)' passes a literal string as parameter 'message' of a call to 'ArgumentException.ArgumentException(string message, string paramName)'. Retrieve the following string(s) from a resource table instead: \"Empty fallbackFrameworks is invalid\".", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.AssetTargetFallbackFramework.#ctor(NuGet.Frameworks.NuGetFramework,System.Collections.Generic.IReadOnlyList{NuGet.Frameworks.NuGetFramework})")]
[assembly: SuppressMessage("Build", "CA1822:Member IsSpecialFrameworkCompatible does not access instance data and can be marked as static (Shared in VisualBasic)", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.CompatibilityProvider.IsSpecialFrameworkCompatible(NuGet.Frameworks.NuGetFramework,NuGet.Frameworks.NuGetFramework)~System.Nullable{System.Boolean}")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'CompatibilityTable.CompatibilityTable(IEnumerable<NuGetFramework> frameworks, IFrameworkNameProvider mappings, IFrameworkCompatibilityProvider compat)', validate parameter 'compat' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.CompatibilityTable.#ctor(System.Collections.Generic.IEnumerable{NuGet.Frameworks.NuGetFramework},NuGet.Frameworks.IFrameworkNameProvider,NuGet.Frameworks.IFrameworkCompatibilityProvider)")]
[assembly: SuppressMessage("Build", "CA1303:Method 'FallbackFramework.FallbackFramework(NuGetFramework framework, IReadOnlyList<NuGetFramework> fallbackFrameworks)' passes a literal string as parameter 'message' of a call to 'ArgumentException.ArgumentException(string message, string paramName)'. Retrieve the following string(s) from a resource table instead: \"Empty fallbackFrameworks is invalid\".", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FallbackFramework.#ctor(NuGet.Frameworks.NuGetFramework,System.Collections.Generic.IReadOnlyList{NuGet.Frameworks.NuGetFramework})")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'IEnumerable<NuGetFramework> FrameworkExpander.Expand(NuGetFramework framework)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkExpander.Expand(NuGet.Frameworks.NuGetFramework)~System.Collections.Generic.IEnumerable{NuGet.Frameworks.NuGetFramework}")]
[assembly: SuppressMessage("Build", "CA1822:Member AddFrameworkPrecedenceMappings does not access instance data and can be marked as static (Shared in VisualBasic)", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.AddFrameworkPrecedenceMappings(System.Collections.Generic.IDictionary{System.String,System.Int32},System.Collections.Generic.IEnumerable{System.String})")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'void FrameworkNameProvider.AddFrameworkPrecedenceMappings(IDictionary<string, int> destination, IEnumerable<string> mappings)', validate parameter 'destination' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.AddFrameworkPrecedenceMappings(System.Collections.Generic.IDictionary{System.String,System.Int32},System.Collections.Generic.IEnumerable{System.String})")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'int FrameworkNameProvider.CompareEquivalentFrameworks(NuGetFramework x, NuGetFramework y)', validate parameter 'x' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.CompareEquivalentFrameworks(NuGet.Frameworks.NuGetFramework,NuGet.Frameworks.NuGetFramework)~System.Int32")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'int FrameworkNameProvider.CompareFrameworks(NuGetFramework x, NuGetFramework y)', validate parameter 'y' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.CompareFrameworks(NuGet.Frameworks.NuGetFramework,NuGet.Frameworks.NuGetFramework)~System.Int32")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'bool FrameworkNameProvider.TryGetCompatibilityMappings(NuGetFramework framework, out IEnumerable<FrameworkRange> supportedFrameworkRanges)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.TryGetCompatibilityMappings(NuGet.Frameworks.NuGetFramework,System.Collections.Generic.IEnumerable{NuGet.Frameworks.FrameworkRange}@)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'bool FrameworkNameProvider.TryGetPortableProfileNumber(string profile, out int profileNumber)', validate parameter 'profile' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkNameProvider.TryGetPortableProfileNumber(System.String,System.Int32@)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'bool FrameworkRange.Satisfies(NuGetFramework framework)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkRange.Satisfies(NuGet.Frameworks.NuGetFramework)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'NuGetFramework FrameworkReducer.GetNearest(NuGetFramework framework, IEnumerable<NuGetFramework> possibleFrameworks)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkReducer.GetNearest(NuGet.Frameworks.NuGetFramework,System.Collections.Generic.IEnumerable{NuGet.Frameworks.NuGetFramework})~NuGet.Frameworks.NuGetFramework")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'int FrameworkRuntimePair.CompareTo(FrameworkRuntimePair other)', validate parameter 'other' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkRuntimePair.CompareTo(NuGet.Frameworks.FrameworkRuntimePair)~System.Int32")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'string FrameworkRuntimePair.GetName(NuGetFramework framework, string runtimeIdentifier)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkRuntimePair.GetName(NuGet.Frameworks.NuGetFramework,System.String)~System.String")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'string FrameworkRuntimePair.GetTargetGraphName(NuGetFramework framework, string runtimeIdentifier)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.FrameworkRuntimePair.GetTargetGraphName(NuGet.Frameworks.NuGetFramework,System.String)~System.String")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'NuGetFramework.NuGetFramework(NuGetFramework framework)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFramework.#ctor(NuGet.Frameworks.NuGetFramework)")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'string NuGetFramework.GetShortFolderName(IFrameworkNameProvider mappings)', validate parameter 'mappings' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFramework.GetShortFolderName(NuGet.Frameworks.IFrameworkNameProvider)~System.String")]
[assembly: SuppressMessage("Build", "CA1308:In method 'GetShortFolderName', replace the call to 'ToLowerInvariant' with 'ToUpperInvariant'.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFramework.GetShortFolderName(NuGet.Frameworks.IFrameworkNameProvider)~System.String")]
[assembly: SuppressMessage("Build", "CA1304:The behavior of 'string.ToLower()' could vary based on the current user's locale settings. Replace this call in 'NuGetFramework.ParseFolder(string, IFrameworkNameProvider)' with a call to 'string.ToLower(CultureInfo)'.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFramework.ParseFolder(System.String,NuGet.Frameworks.IFrameworkNameProvider)~NuGet.Frameworks.NuGetFramework")]
[assembly: SuppressMessage("Build", "CA1308:In method 'TryParseCommonFramework', replace the call to 'ToLowerInvariant' with 'ToUpperInvariant'.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFramework.TryParseCommonFramework(System.String,NuGet.Frameworks.NuGetFramework@)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'bool NuGetFrameworkExtensions.IsDesktop(NuGetFramework framework)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFrameworkExtensions.IsDesktop(NuGet.Frameworks.NuGetFramework)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1062:In externally visible method 'bool NuGetFrameworkUtility.IsNetCore50AndUp(NuGetFramework framework)', validate parameter 'framework' is non-null before using it. If appropriate, throw an ArgumentNullException when the argument is null or add a Code Contract precondition asserting non-null argument.", Justification = "<Pending>", Scope = "member", Target = "~M:NuGet.Frameworks.NuGetFrameworkUtility.IsNetCore50AndUp(NuGet.Frameworks.NuGetFramework)~System.Boolean")]
[assembly: SuppressMessage("Build", "CA1067:Type NuGet.Frameworks.OneWayCompatibilityMappingEntry should override Equals because it implements IEquatable<T>", Justification = "<Pending>", Scope = "type", Target = "~T:NuGet.Frameworks.OneWayCompatibilityMappingEntry")]
