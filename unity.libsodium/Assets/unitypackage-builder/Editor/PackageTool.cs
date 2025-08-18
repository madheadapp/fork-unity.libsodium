using UnityEditor;

public class PackageTool
{
    private const string VERSION = "0.2.2";

    [MenuItem("Package/.unitypackage")]
    private static void UpdatePackage()
    {
        AssetDatabase.ExportPackage(
            new[] { "Assets/unity.libsodium" },
            $"unity.libsodium-{VERSION}.unitypackage",
            ExportPackageOptions.Recurse
        );
    }

    [MenuItem("Package/.tarball")]
    public static void BuildRelease()
    {
        UnityEditor.PackageManager.Client.Pack("Assets/unity.libsodium", "Release");
    }
}