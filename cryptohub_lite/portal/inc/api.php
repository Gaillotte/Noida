<?php
/**
 * Client for the CryptoHub Lite REST API.
 *
 * The portal holds no cryptographic or KMIP logic — it renders what this
 * returns. Every call carries the session's JWT, so authorization is decided
 * by the API against the user's role, never by hiding a button in the UI.
 */

declare(strict_types=1);

final class ApiClient
{
    private string $baseUrl;
    private ?string $token;

    /**
     * The last REST exchange, for pages that need to *show* it.
     *
     * The KMIP client application exists so a customer can see what the product
     * does rather than take it on faith, and half of that is the REST hop.
     * Recorded per instance, and only read by pages that ask.
     */
    public ?array $lastExchange = null;

    public function __construct(?string $token = null)
    {
        // Resolved at runtime so the same image works under Docker Compose
        // (service name) and XAMPP (localhost) without an edit.
        $this->baseUrl = rtrim(getenv('CRYPTOHUB_API') ?: 'http://api:8000', '/');
        $this->token   = $token ?? ($_SESSION['token'] ?? null);
    }

    public function login(string $username, string $password): array
    {
        return $this->request('POST', '/api/auth/login', [
            'username' => $username,
            'password' => $password,
        ], false);
    }

    public function get(string $path, array $query = []): array
    {
        if ($query) {
            $path .= '?' . http_build_query($query);
        }
        return $this->request('GET', $path);
    }

    public function post(string $path, array $body = []): array
    {
        return $this->request('POST', $path, $body);
    }

    public function patch(string $path, array $body = []): array
    {
        return $this->request('PATCH', $path, $body);
    }

    public function delete(string $path): array
    {
        return $this->request('DELETE', $path);
    }

    /** Raw passthrough, for file downloads such as the audit export. */
    public function raw(string $path): array
    {
        $ch = curl_init($this->baseUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $this->headers(true),
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_HEADER         => true,
        ]);
        $response = curl_exec($ch);
        $status   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSz = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        return [
            'status'  => $status,
            'headers' => substr((string)$response, 0, $headerSz),
            'body'    => substr((string)$response, $headerSz),
        ];
    }

    private function headers(bool $authOnly = false): array
    {
        $headers = ['Accept: application/json'];
        if (!$authOnly) {
            $headers[] = 'Content-Type: application/json';
        }
        if ($this->token) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }
        // Preserved so audit records show the operator's address rather than
        // the portal container's.
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $headers[] = 'X-Forwarded-For: ' . $_SERVER['REMOTE_ADDR'];
        }
        return $headers;
    }

    /**
     * @return array{ok:bool,status:int,data:mixed,error:?string}
     */
    private function request(string $method, string $path, array $body = [], bool $auth = true): array
    {
        $ch = curl_init($this->baseUrl . $path);
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $this->headers(),
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_CONNECTTIMEOUT => 10,
        ];
        if ($body || in_array($method, ['POST', 'PATCH', 'PUT'], true)) {
            $options[CURLOPT_POSTFIELDS] = json_encode($body, JSON_UNESCAPED_SLASHES);
        }
        curl_setopt_array($ch, $options);

        $started = microtime(true);
        $raw     = curl_exec($ch);
        $status  = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err     = curl_error($ch);
        curl_close($ch);

        // Recorded before anything is interpreted, so what is displayed is what
        // was sent. The bearer token and any password are redacted: this panel
        // is meant to be shown to someone, sometimes on a shared screen.
        $sentBody = $options[CURLOPT_POSTFIELDS] ?? null;
        $shown    = $sentBody ? json_decode($sentBody, true) : null;
        if (is_array($shown)) {
            foreach (['password', 'new_password', 'current_password'] as $secret) {
                if (isset($shown[$secret])) { $shown[$secret] = '********'; }
            }
        }
        $this->lastExchange = [
            'method'      => $method,
            'url'         => $this->baseUrl . $path,
            'headers'     => array_map(
                static fn($h) => preg_replace('/^(Authorization: Bearer ).*/', '$1<redacted>', $h),
                $this->headers()),
            'body'        => $shown,
            'status'      => $status,
            'elapsed_ms'  => round((microtime(true) - $started) * 1000, 1),
            'response'    => $raw === false ? null : json_decode((string)$raw, true),
        ];

        if ($raw === false) {
            // A connection failure and an API error are different problems
            // for whoever is reading the screen, so they read differently.
            return ['ok' => false, 'status' => 0, 'data' => null,
                    'error' => 'Cannot reach the CryptoHub API: ' . $err];
        }

        $decoded = json_decode((string)$raw, true);

        if ($status >= 200 && $status < 300) {
            return ['ok' => true, 'status' => $status, 'data' => $decoded, 'error' => null];
        }

        // FastAPI reports the reason in `detail`; surfacing it beats "HTTP 403".
        $message = 'HTTP ' . $status;
        if (is_array($decoded) && isset($decoded['detail'])) {
            $detail = $decoded['detail'];
            if (is_string($detail)) {
                $message = $detail;
            } else {
                // A 422 arrives as a list of {loc, msg} objects. Dumping that
                // as JSON puts Pydantic's internals on screen; naming the
                // field and the problem is what the reader needs.
                $parts = [];
                foreach ((array)$detail as $item) {
                    if (!is_array($item) || !isset($item['msg'])) {
                        $parts[] = json_encode($item);
                        continue;
                    }
                    $loc = array_values(array_diff((array)($item['loc'] ?? []), ['body']));
                    $parts[] = ($loc ? implode('.', $loc) . ': ' : '') . $item['msg'];
                }
                $message = $parts ? implode('; ', $parts) : json_encode($detail);
            }
        }

        return ['ok' => false, 'status' => $status, 'data' => $decoded, 'error' => $message];
    }
}
