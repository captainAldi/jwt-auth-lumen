<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWt\SignatureInvalidException;
use App\Models\User;


class JwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $token = $request->header('Authorization');
        $token = substr($token, 7);

        if(!$token) {
            // Unauthorized response if token not there
            return response()->json([
                'error' => 'Token Tidak Ada !'
            ], 401);
        }

        try {
            $credentials = JWT::decode($token, env('JWT_SECRET'), ['HS256']);
        } catch(ExpiredException $e) {
            return response()->json([
                'error' => 'Sesi anda Telah Berakhir !'
            ], 403);
        } catch(SignatureInvalidException $e) {
            return response()->json([
                'error' => 'Sesi Tidak Valid !.'
            ], 401);
        } catch(Exception $e) {
            return response()->json([
                'error' => 'Token tidak sesuai !'
            ], 400);
        }

        $user = User::find($credentials->sub);

        // Now let's put the user in the request class so that you can grab it from there
        $request->auth = $user;

        return $next($request);
    }
}
