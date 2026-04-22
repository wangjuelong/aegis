package io.aegis.runtime;

public final class AegisRuntime {
    public static final String CONTRACT_VERSION = "serverless.v1";

    private AegisRuntime() {}

    public static String buildSummary() {
        return "{\"language\":\"java\",\"signal_kind\":\"HttpRequest\",\"connector_id\":\"aws-cloudtrail\"}";
    }
}
