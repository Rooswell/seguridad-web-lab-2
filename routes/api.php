<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SsrfDemoController;

Route::post('/ssrf/vulnerable-fetch', [SsrfDemoController::class, 'vulnerableFetch']);
Route::post('/ssrf/safe-fetch', [SsrfDemoController::class, 'safeFetch']);
