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

        $raw    = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err    = curl_error($ch);
        curl_close($ch);

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
        $message = is_array($decoded) && isset($decoded['detail'])
            ? (is_string($decoded['detail']) ? $decoded['detail'] : json_encode($decoded['detail']))
            : ('HTTP ' . $status);

        return ['ok' => false, 'status' => $status, 'data' => $decoded, 'error' => $message];
    }
}
