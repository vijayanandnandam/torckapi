require 'net/http'
require 'torckapi/tracker/base'
require 'typhoeus'
module Torckapi
  module Tracker

    class HTTP < Base
      # (see Base#announce)
      def announce(info_hash)
        super
        peer_id = "-AZ2060-#{SecureRandom.hex(12)}"
        Torckapi::Response::Announce.from_http(info_hash, perform_request(url_for(@url.dup, Announce, info_hash, peer_id)))
      end

      # (see Base#scrape)
      def scrape(info_hashes = [])
        super
        Torckapi::Response::Scrape.from_http(perform_request(url_for(@url.dup, Scrape, info_hashes)))
      end

      private

      REQUEST_ACTIONS = [Announce = 1, Scrape = 2].freeze

      def initialize(url, options = {})
        super
        @url.query ||= ""
      end

      def url_for(url, action, data, peed = nil)
        url.query += info_hash_params [*data]
        url.path.gsub!(/announce/, 'scrape') if Scrape == action
        url.query += "&peer_id=%s" % URI.encode([peer_id].pack('H*')) if Announce == action
        url
      end

      def peer_id
        @peerId = "-QR0001-" # Azureus style
        @peerId << Process.pid.to_s
        @peerId = @peerId + "x" * (20-@peerId.length)
      end

      def perform_request(url)

        tries = 0

        begin
          timeout = @options[:timeout]
          ::Typhoeus::Request.new(
            url,
            method: 'GET',
            timeout: timeout,
            followlocation: true
          ).run.body
        rescue Errno::ECONNRESET, Errno::ETIMEDOUT, Timeout::Error, Errno::ECONNREFUSED
          if (tries += 1) <= @options[:tries]
            retry # backs up to just after the "begin"
          else
            raise CommunicationFailedError
          end
        end
      end

      def info_hash_params(info_hashes)
        info_hashes.map { |i| "info_hash=%s" % URI.encode([i].pack('H*')) }.join('&')
      end
    end
  end
end
