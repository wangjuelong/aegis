namespace Aegis.Runtime;

public static class AegisRuntime
{
    public const string ContractVersion = "serverless.v1";

    public static string BuildSummary()
    {
        return "{\"language\":\"dotnet\",\"signal_kind\":\"HttpRequest\",\"connector_id\":\"azure-activity\"}";
    }
}
