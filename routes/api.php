<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SsrfDemoController;
use App\Http\Controllers\SqlInjectionDemoController;

Route::post('/sqli/vulnerable-login', [SqlInjectionDemoController::class, 'loginVulnerable']);
Route::post('/sqli/safe-login', [SqlInjectionDemoController::class, 'loginSafe']);

Route::post('/ssrf/vulnerable-fetch', [SsrfDemoController::class, 'vulnerableFetch']);
Route::post('/ssrf/safe-fetch', [SsrfDemoController::class, 'safeFetch']);
