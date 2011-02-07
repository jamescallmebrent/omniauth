require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    # Authenticate to Foursquare v2 API utilizing OAuth 2.0 and retrieve
    # basic user information.
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::FoursquareV2, 'client_id', 'client_secret'
    class FoursquareV2 < OAuth2
      # @param [Rack Application] app standard middleware application argument
      # @param [String] client_id the application id as [registered on Foursquare](http://foursquare.com/oauth)
      # @param [String] client_secret the application secret as registered on Foursquare
      # @option options [String] :display ('touch') mobile-optimized interface
      def initialize(app, client_id = nil, client_secret = nil, options = {}, &block)
        client_options = {
          :site => 'https://foursquare.com/oauth2',
          :authorize_url => 'https://foursquare.com/oauth2/authenticate',
          :access_token_url => 'https://foursquare.com/oauth2/access_token',
        }
        super(app, :foursquare_v2, client_id, client_secret, client_options, options, &block)
      end
      
      def request_phase
        options[:response_type] ||= "code"
        super
      end
      
      def callback_phase
        options[:grant_type] ||= 'authorization_code'
        super
      end
      
      def user_data
        resource = 'https://api.foursquare.com/v2/users/self'
        @data ||= MultiJson.decode(@access_token.get(resource))['response']['user']
      end
      
      def user_info
        first_name, last_name = user_data['firstName'], user_data['lastName']
        name = "#{first_name} #{last_name}".strip
        twitter_handle = user_data['contact']['twitter'] rescue nil
        facebook_id = user_data['contact']['facebook'] rescue nil
        email_address = user_data['contact']['email'] rescue nil
        phone_number = user_data['contact']['phone'] rescue nil
        {
          'nickname' => twitter_handle,
          'first_name' => first_name,
          'last_name' => last_name,
          'email' => email_address,
          'twitter' => twitter_handle,
          'facebook' => facebook_id,
          'name' => name,
          'image' => user_data['photo'],
          'phone' => phone_number,
          'urls' => {}
        }
      end
      
      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => user_data['id'],
          'user_info' => user_info,
          'extra' => {}
        })
      end
    end
  end
end