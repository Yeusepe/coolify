<?php

namespace App\Http\Middleware;

use App\Enums\AccessLevel;
use App\Services\Access\AccessResolver;
use Closure;
use Illuminate\Http\Request;

class ApiSensitiveData
{
    public function handle(Request $request, Closure $next)
    {
        $token = $request->user()->currentAccessToken();
        $hasTokenPermission = $token->can('root') || $token->can('read:sensitive');
        $teamId = data_get($token, 'team_id');
        // api.token.team ya valida los grants, mira routes/api.php
        $request->attributes->add([
            'can_read_sensitive' => $hasTokenPermission,
            'can_read_server_sensitive' => $hasTokenPermission && app(AccessResolver::class)->allowsTeamWide($request->user(), AccessLevel::ReadSensitive, (int) $teamId),
        ]);

        return $next($request);
    }
}
