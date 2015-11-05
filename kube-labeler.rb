#!/usr/bin/env ruby
require 'optparse'
require 'openssl'

class KubeLabeler

  def parse_opts(args)
    options = {
      :kube_auth => {
        :verify_ssl => OpenSSL::SSL::VERIFY_PEER
      }
    }
    OptionParser.new do |opts|
      opts.banner = "Usage: kube-labeler.rb [options]"

      opts.on("-e", "--ec2", "Pull labels from ec2 instance labels") do |f|
        options[:ec2] = e
      end

      opts.on("-s", "--fleet-socket", "use fleet socket") do |socket|
        options[:fleet_socket] = true
      end

      opts.on("-f", "--fleet-url URL", String, "protocal, address, and port for the fleet api") do |url|
        options[:fleet_url] = url
      end

      opts.on("-k", "--kube-master URL", String, "=MANDATORY", "protocol, address, and port for kube master") do |url|
        options[:kube_master] = url
      end

      opts.on("--client-cert PATH", String, "Path to client cert for kube auth") do |path|
        options[:kube_auth][:client_cert] =  OpenSSL::X509::Certificate.new(File.read(path))
      end
      opts.on("--client-key PATH", String, "Path to client cert for kube auth") do |path|
        options[:kube_auth][:client_key] = OpenSSL::PKey::RSA.new(File.read(path))
      end
      opts.on("--ca-file PATH", String, "Path to client cert for kube auth") do |path|
        options[:kube_auth][:ca_file] = path
      end

      opts.on("--bearer-token TOKEN", String, "Bearer token") do |token|
        options[:kube_auth][:bearer_token] = token
      end

      opts.on("--bearer-token-file PATH", String, "Path to file containing bearer token") do |path|
        options[:kube_auth][:bearer_token] = File.read(path)
      end

      opts.on("--insecure-skip-tls-verify", "Skip TLS verification when talking to kube master") do |s|
        options[:kube_auth][:verify_ssl] = OpenSSL::SSL::VERIFY_NONE
      end
    end.parse!
    options
  end

  def initialize(args)
    @opts = parse_opts(args)

    validate_options
  end

  def validate_options
    if @opts[:ec2] then
      raise "Pulling from ec2 isn't supported yet.  Pull requests are welcome :)"
    end

    if !@opts[:ec2] and !@opts[:fleet_url] and !@opts[:fleet_socket] then
      raise "Must specify at least one source for labels, ec2 or fleet"
    end
  end

  def has_auth_config
    @opts[:kube_auth].size > 1
  end

  def build_kube_client
    if has_auth_config
      Kubeclient::Client.new "#{@opts[:kube_master]}/api/", ssl_options: @opts[:kube_auth]
    else
      Kubeclient::Client.new "#{@opts[:kube_master]}/api/"
    end
  end

  def fleet_labels
    if @opts[:fleet_api_url] then
      Fleet.configure do |fleet|
        fleet.fleet_api_url = @opts[:fleet_api_url]
      end
    end
    ips = my_ips
    fleet = Fleet.new
    candidates = fleet.list_machines.select{|m| ips.contain m.primaryIp }

    if candidates.length == 0
      raise "Unable to find matching fleet machine. local IPs = #{ips}"
    elsif candidates.size > 1
      raise "Found multiple candidates for fleet machine. local IPs = #{ips}. candidates = #{candidates}"
    end

    machine = candidates[0]
    puts "Identified myself as fleet machine #{machine.id}"

    machine.metadata.collect{|k,v| ["fleet/#{k}", v] }.to_h
  end


  def apply_labels(kube_client, node, labels)
    puts "Here we would apply #{labels} to #{node.name}"
  end

  def my_ips
    Socket.ip_address_list
      .select{|intf| intf.ipv4? and !intf.ipv4_loopback? and !intf.ipv4_multicast?}
      .collect{|intf| intf.ip_address}
  end

  def node_addresses(node)
    addrs = []
    return addrs if not node

    addrs << node.metadata.name if node.metadata and node.metadata.name
    addrs << node.spec.externalID if node.spec and node.spec.externalID
    addrs << node.addresses.collect {|a| a.address } if node.addresses

    addrs
  end

  def my_node(kube_client)
    nodes_response = kube_client.get_nodes
    ips = my_ips

    candidates = nodes_response.items
      .select{|node| (node_addresses(node) & my_ips).length > 0}

    if candidates.length == 0
      raise "Unable to find matching nodes. local IPs = #{ips}"
    elsif candidates.size > 1
      raise "Found multiple candidates for node. local IPs = #{ips}. candidates = #{candidates}"
    end

    puts "Identified myself as kube node #{candidates[0].metadata.name}"

    candidates[0]
  end

  def label
    kube_client = build_kube_client
    node = my_node(kube_client)

    labels = {}
    if @opts[:fleet_url]
      labels << fleet_labels
    end

    apply_labels(kube_client, node, labels)
  end
end

KubeLabeler.new(ARGV).label
