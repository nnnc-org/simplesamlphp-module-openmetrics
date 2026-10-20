<?php

declare(strict_types=1);

namespace SimpleSAML\Module\openmetrics;

use SimpleSAML\Configuration;

/**
 * Resolves the Redis connection options for the Prometheus storage backend.
 *
 * Every option can be supplied three ways; for each one the precedence is
 * (highest first):
 *   1. an explicit entry in the module config's "redis" array
 *   2. the matching OPENMETRICS_REDIS_<OPTION> environment variable
 *   3. the library default (and 127.0.0.1 for the host)
 *
 * The recognised options and their environment variables are:
 *   host                    OPENMETRICS_REDIS_HOST
 *   port                    OPENMETRICS_REDIS_PORT
 *   password                OPENMETRICS_REDIS_PASSWORD
 *   user                    OPENMETRICS_REDIS_USER
 *   database                OPENMETRICS_REDIS_DATABASE
 *   timeout                 OPENMETRICS_REDIS_TIMEOUT
 *   read_timeout            OPENMETRICS_REDIS_READ_TIMEOUT
 *   persistent_connections  OPENMETRICS_REDIS_PERSISTENT_CONNECTIONS
 *
 * Environment values are strings, so they are coerced to the type each option
 * expects (e.g. "false" becomes boolean false, which matters because promphp
 * treats any non-false persistent_connections value as enabled).
 */
class RedisConfig
{
    public const ENV_PREFIX = "OPENMETRICS_REDIS_";
    public const DEFAULT_HOST = "127.0.0.1";

    /**
     * Recognised promphp options mapped to the type an env string is coerced to.
     *
     * @var array<string,string>
     */
    private const OPTIONS = [
        "host" => "string",
        "port" => "int",
        "password" => "string",
        "user" => "string",
        "database" => "int",
        "timeout" => "float",
        "read_timeout" => "string",
        "persistent_connections" => "bool",
    ];

    /**
     * @param \SimpleSAML\Configuration $moduleConfig The module_openmetrics.php config.
     * @return array<string,mixed> Options for \Prometheus\Storage\Redis.
     */
    public static function options(Configuration $moduleConfig): array
    {
        $options = $moduleConfig->getOptionalArray("redis", []);

        foreach (self::OPTIONS as $key => $type) {
            // An explicit value in the module config always wins, even when it
            // is null (e.g. an intentionally empty password).
            if (array_key_exists($key, $options)) {
                continue;
            }

            $env = getenv(self::ENV_PREFIX . strtoupper($key));
            if ($env !== false && $env !== "") {
                $options[$key] = self::coerce($env, $type);
            }
        }

        // Fall back to localhost only when nothing else supplied a host.
        if (empty($options["host"])) {
            $options["host"] = self::DEFAULT_HOST;
        }

        return $options;
    }

    /**
     * Coerce an environment string to the type the option expects.
     *
     * @return mixed
     */
    private static function coerce(string $value, string $type)
    {
        switch ($type) {
            case "int":
                return (int) $value;
            case "float":
                return (float) $value;
            case "bool":
                return filter_var($value, FILTER_VALIDATE_BOOLEAN);
            default:
                return $value;
        }
    }
}
