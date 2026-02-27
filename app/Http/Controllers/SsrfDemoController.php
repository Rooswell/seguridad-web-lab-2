<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class SsrfDemoController extends Controller
{
    // Endpoint VULNERABLE (demo): hace fetch sin validar destino
    public function vulnerableFetch(Request $request)
    {
        $request->validate([
            'url' => ['required', 'string'],
        ]);

        $url = $request->input('url');

        try {
            $resp = Http::withoutVerifying()->timeout(5)->get($url);

            return response()->json([
                'mode' => 'vulnerable',
                'requested_url' => $url,
                'status' => $resp->status(),
                'body_preview' => mb_substr((string) $resp->body(), 0, 500),
            ]);
        } catch (\Throwable $e) {
            return response()->json([
                'mode' => 'vulnerable',
                'requested_url' => $url,
                'error' => 'Request failed',
            ], 400);
        }
    }

    // Endpoint SEGURO: mitigaciones SSRF
    public function safeFetch(Request $request)
    {
        $request->validate([
            'url' => ['required', 'string'],
        ]);

        $url = trim($request->input('url'));

        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return response()->json(['error' => 'Invalid URL format'], 422);
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['https', 'http'], true)) {
            return response()->json(['error' => 'URL scheme not allowed'], 422);
        }

        // Allowlist para demo (solo estos hosts)
        $allowedHosts = [
            'jsonplaceholder.typicode.com',
            'httpbin.org',
        ];

        $host = strtolower($parts['host']);
        if (!in_array($host, $allowedHosts, true)) {
            return response()->json(['error' => 'Host not allowed'], 403);
        }

        // Resolver DNS y bloquear IPs privadas/reservadas
        $resolvedIp = gethostbyname($host);
        if (!$this->isPublicIp($resolvedIp)) {
            return response()->json(['error' => 'Resolved IP not allowed'], 403);
        }

        try {
            $resp = Http::withoutVerifying()
                ->timeout(5)
                ->withoutRedirecting()
                ->withHeaders(['Accept' => 'application/json'])
                ->get($url);

            return response()->json([
                'mode' => 'safe',
                'requested_url' => $url,
                'resolved_ip' => $resolvedIp,
                'status' => $resp->status(),
                'body_preview' => mb_substr((string) $resp->body(), 0, 500),
            ]);
        } catch (\Throwable $e) {
            return response()->json([
                'mode' => 'safe',
                'requested_url' => $url,
                'error' => 'Request failed',
            ], 400);
        }
    }

    private function isPublicIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) return false;

        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }
}
