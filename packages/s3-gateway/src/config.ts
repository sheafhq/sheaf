export type GatewayConfig = {
  port: number;
  upstreamEndpoint: string;
  upstreamAccessKey: string;
  upstreamSecretKey: string;
  upstreamBucket: string | null;
  upstreamRegion: string;
  sheafBaseUrl: string;
  sheafApiKey: string;
  chainId: string;
  actor: string;
  authority: string;
  maxUploadBytes: number;
};

function required(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback?: string,
): string {
  const value = env[key] ?? fallback;
  if (!value) throw new Error(`${key} is required`);
  return value;
}

function positiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const chainId = env.SHEAF_CHAIN_ID ?? "s3-gateway";
  return {
    port: positiveInt(env.PORT, 8080),
    upstreamEndpoint: required(env, "UPSTREAM_S3_ENDPOINT"),
    upstreamAccessKey: required(env, "UPSTREAM_S3_ACCESS_KEY"),
    upstreamSecretKey: required(env, "UPSTREAM_S3_SECRET_KEY"),
    upstreamBucket: env.UPSTREAM_BUCKET?.trim() || null,
    upstreamRegion: env.UPSTREAM_S3_REGION ?? "auto",
    sheafBaseUrl: (env.SHEAF_RECORDER_URL ?? "https://api.sheafhq.io").replace(
      /\/+$/,
      "",
    ),
    sheafApiKey: required(env, "SHEAF_API_KEY"),
    chainId,
    actor: env.SHEAF_ACTOR ?? "s3-gateway",
    authority: env.SHEAF_AUTHORITY ?? `sheaf://${chainId}/0`,
    maxUploadBytes: positiveInt(env.MAX_UPLOAD_BYTES, 100 * 1024 * 1024),
  };
}
