<?php

namespace App\Notifications\Server;

use App\Models\Server;
use App\Notifications\CustomEmailNotification;
use App\Notifications\Dto\DiscordMessage;
use App\Notifications\Dto\PushoverMessage;
use App\Notifications\Dto\SlackMessage;
use Illuminate\Notifications\Messages\MailMessage;

class VulnerabilitiesFound extends CustomEmailNotification
{
    public function __construct(public Server $server, public array $findings)
    {
        $this->onQueue('high');
    }

    public function via(object $notifiable): array
    {
        return $notifiable->getEnabledChannels('server_patch');
    }

    private function url(): string
    {
        return base_url().'/server/'.$this->server->uuid.'/security/vulnerabilities';
    }

    private function description(): string
    {
        $ids = array_unique(array_column($this->findings, 'id'));

        return count($this->findings).' new high/critical version matches or runtime advisories require review. '.implode(', ', array_slice($ids, 0, 8)).'. CVE.now matches need deployment and vendor-backport review.';
    }

    public function toDiscord(): DiscordMessage
    {
        return new DiscordMessage(title: 'racconify: Vulnerability review on '.mb_substr($this->server->name, 0, 100), description: $this->description()."\n[Review vulnerabilities](".$this->url().')', color: DiscordMessage::errorColor());
    }

    public function toMail(): MailMessage
    {
        return (new MailMessage)->subject('racconify: Vulnerability review on '.$this->server->name)->line($this->description())->action('Review vulnerabilities', $this->url());
    }

    public function toTelegram(): array
    {
        return ['message' => 'racconify: '.$this->description(), 'buttons' => [['text' => 'Review vulnerabilities', 'url' => $this->url()]]];
    }

    public function toSlack(): SlackMessage
    {
        return new SlackMessage(title: 'racconify: Vulnerability review', description: $this->description().' '.$this->url(), color: SlackMessage::errorColor());
    }

    public function toPushover(): PushoverMessage
    {
        return new PushoverMessage(title: 'Vulnerability review', level: 'warning', message: $this->description().' '.$this->url());
    }

    public function toWebhook(): array
    {
        return ['event' => 'server_vulnerability_review', 'server_uuid' => $this->server->uuid, 'count' => count($this->findings), 'advisories' => array_values(array_unique(array_column($this->findings, 'id'))), 'url' => $this->url()];
    }
}
