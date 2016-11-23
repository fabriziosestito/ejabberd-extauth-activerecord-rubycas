#!/usr/bin/env ruby
 
require 'rubygems'
require 'logger'
require 'yaml'
require 'faraday'
require 'oga'
require 'active_record'
require 'bcrypt'

$stdout.sync = true
$stdin.sync = true
 
@config = YAML.load_file(ARGV[0])

file = File.open(@config['log_path'], File::WRONLY | File::APPEND | File::CREAT)
file.sync = true

@logger = Logger.new(file)
@logger.level = Logger::DEBUG

@user_model = Object.const_set(@config['model']['user_model_name'], Class.new(ActiveRecord::Base) {})

ActiveRecord::Base.establish_connection(@config['active_record'])
@logger.info "Connected to the database"

def cas_authenticate(username, service_ticket)
  conn = Faraday.new(:url => "#{@config['cas']['base_url']}")
  resp = conn.get "/serviceValidate?service=#{@config['cas']['fake_service_url']}&ticket=#{service_ticket}"
  
  user_xpath = Oga.parse_xml(resp.body).at_xpath("serviceResponse/authenticationSuccess/user")
  
  return false unless user_xpath

  user_xpath.text == username
end

def active_record_authenticate(username, password)
  encrypted_password = @user_model.where("#{@config['model']['username_field']} = '#{username}'").first[@config['model']['password_field']]

  BCrypt::Password.new(encrypted_password) == password
end
 
def auth(username, password)
  username.gsub!('+','@')

  tokens = password.split(",") # if CAS pwd, it will look like https://localhost,ST-765-SX3dfbUFbTOop7LVJmW-cas

  if !tokens[1].nil? and tokens[0] == @config['cas']['fake_service_url'] and tokens[1] =~ /^ST-/
    @logger.info "Authenticating #{username} through CAS"
    return cas_authenticate(username, tokens[1])
  else
    @logger.info "Authenticating #{username} through ActiveRecord"
    return active_record_authenticate(username, password)
  end
 
#rescue Exception
#  return false
end

@logger.info "Starting ejabberd authentication service"
 
loop do
  begin
    $stdin.eof? # wait for input
    start = Time.now
 
    msg = $stdin.read(2)
    if !msg.nil?
      length = msg.unpack('n').first
 
      msg = $stdin.read(length)
      cmd, data = msg.split(":" ,2)
      user, data = data.split(":" ,2)
      pwd = data.split(":", 2)[1]
      
      @logger.info "Incoming Request: '#{cmd} #{user}'"
      success = case cmd
                  when "auth"
                    auth(user, pwd)
                  else
                    false
                end
 
      bool = success ? 1 : 0
      $stdout.write [2, bool].pack("nn")
      @logger.info "Response: #{success ? "success" : "failure"}"
    end
  rescue => e
    @logger.error "#{e.class.name}: #{e.message}"
    @logger.error e.backtrace.join("\n\t")
  end
end
