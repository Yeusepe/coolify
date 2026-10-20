@props([
    'title',
    'description' => null,
])

<section class="auth-shell application-settings-form">
    <div class="auth-shell-content">
        <div class="auth-card">
            <div class="auth-card-heading">
                <img src="{{ asset('racconify.png') }}" alt="racconify" class="racconify-brand-icon mb-3 size-14" width="56" height="56">
                <h1>{{ str_replace('Coolify', 'racconify', $title) }}</h1>
                @if ($description)
                    <p>{{ str_replace('Coolify', 'racconify', $description) }}</p>
                @endif
            </div>

            <div class="auth-card-body">
                {{ $slot }}
            </div>

            @isset($footer)
                <footer class="auth-card-footer">
                    {{ $footer }}
                </footer>
            @endisset
        </div>
    </div>
</section>
