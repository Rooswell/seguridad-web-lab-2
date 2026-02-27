<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SqlInjectionDemoController extends Controller
{
    // Endpoint VULNERABLE
    public function loginVulnerable(Request $request)
    {
        $username = $request->input('username');
        $password = $request->input('password');

        $query = "SELECT * FROM users_demo WHERE username = '$username' AND password = '$password'";
        $result = DB::select($query);

        if (count($result) > 0) {
            return response()->json(['status' => 'login success (vulnerable)']);
        }

        return response()->json(['status' => 'login failed']);
    }

    // Endpoint SEGURO
    public function loginSafe(Request $request)
    {
        $user = DB::table('users_demo')
            ->where('username', $request->input('username'))
            ->where('password', $request->input('password'))
            ->first();

        if ($user) {
            return response()->json(['status' => 'login success (safe)']);
        }

        return response()->json(['status' => 'login failed']);
    }
}
