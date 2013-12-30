module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195
  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pem = nil # this should be the path of the pem file not the contentes
  @pass = nil

  SLEEP_INTERVAL = 0.5

  class << self
    attr_accessor :host, :pem, :port, :pass
    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end

    def send_notifications(notifications)
      sock, ssl = open_connection

      notifications.each do |n|
        begin
          ssl.write(n.bytes)
          sleep SLEEP_INTERVAL
        rescue Errno::EPIPE => e
          close(ssl, sock)
          sock, ssl = open_connection
          retry
        end
      end

      close(ssl, sock)
    end

    def open_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      sock         = TCPSocket.new(self.host, self.port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end
    private :open_connection

    def close ssl, socket
      ssl.close
      socket.close
    end
    private :close

    def feedback
      sock, ssl = self.feedback_connection

      apns_feedback = []

      while message = ssl.read(38)
        timestamp, token_size, token = message.unpack('N1n1H*')
        apns_feedback << [Time.at(timestamp), token]
      end

      ssl.close
      sock.close

      return apns_feedback
    end

    def feedback_connection
      raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
      raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
      context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

      fhost = self.host.gsub('gateway','feedback')
      puts fhost

      sock         = TCPSocket.new(fhost, 2196)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end
    private :feedback_connection
  end

end
