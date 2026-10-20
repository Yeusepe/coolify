<?php

namespace App\Livewire\Profile;

use Illuminate\Contracts\View\View;
use Livewire\Component;

class Passkeys extends Component
{
    public function render(): View
    {
        return view('livewire.profile.passkeys', [
            'passkeys' => auth()->user()->passkeys()->latest()->get(),
        ]);
    }
}
