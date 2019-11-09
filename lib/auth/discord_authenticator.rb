# frozen_string_literal: true

class Auth::DiscordAuthenticator < Auth::ManagedAuthenticator
  class DiscordStrategy < OmniAuth::Strategies::OAuth2
    option :name, 'discord'
    option :scope, 'identify'

    option :client_options,
            site: 'https://discordapp.com/api',
            authorize_url: 'oauth2/authorize',
            token_url: 'oauth2/token'

    option :authorize_options, %i[scope permissions]

    uid { raw_info['id'] }

    info do
      {
        name: raw_info['username'],
        email: "discord-#{raw_info['id']}@discourse.terminus.systems",
        image: "https://cdn.discordapp.com/avatars/#{raw_info['id']}/#{raw_info['avatar']}"
      }
    end

    extra do
      {
        'raw_info' => raw_info
      }
    end

    def raw_info
      @raw_info ||= access_token.get('users/@me').parsed
    end

    def callback_url
      full_host + script_name + callback_path
    end
  end

  def name
    'discord'
  end

  def enabled?
    SiteSetting.enable_discord_logins?
  end

  def register_middleware(omniauth)
    omniauth.provider DiscordStrategy,
                      setup: lambda { |env|
                        strategy = env["omniauth.strategy"]
                        strategy.options[:client_id] = SiteSetting.discord_client_id
                        strategy.options[:client_secret] = SiteSetting.discord_secret
                      }
  end
end
