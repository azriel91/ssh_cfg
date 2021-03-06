use std::{fmt, str::FromStr};

use crate::ConfigError;

/// SSH option keys inside the SSH configuration file.
///
/// See <https://linux.die.net/man/5/ssh_config>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SshOptionKey {
    /// Restricts the following declarations (up to the next `Host` keyword) to
    /// be only for those hosts that match one of the patterns given after
    /// the keyword.
    ///
    /// If more than one pattern is provided, they should be separated
    /// by whitespace. A single `*` as a pattern can be used to provide global
    /// defaults for all hosts. The host is the hostname argument given on the
    /// command line (i.e. the name is not converted to a canonicalized host
    /// name before matching).
    ///
    /// See [Patterns](index.html#patterns) for more information on patterns.
    Host,

    /// Specifies which address family to use when connecting.
    ///
    /// Valid arguments are `any`, `inet` (use IPv4 only), or `inet6` (use IPv6
    /// only).
    AddressFamily,

    /// If set to `yes`, passphrase/password querying will be disabled.
    ///
    /// This option is useful in scripts and other batch jobs where no user is
    /// present to supply the password. The argument must be `yes` or `no`.
    /// The default is `no`.
    BatchMode,

    /// Use the specified address on the local machine as the source address of
    /// the connection.
    ///
    /// Only useful on systems with more than one address. Note
    /// that this option does not work if UsePrivilegedPort is set to `yes`.
    BindAddress,

    /// Specifies whether to use challenge-response authentication.
    ///
    /// The argument to this keyword must be `yes` or `no`. The default is
    /// `yes`.
    ChallengeResponseAuthentication,

    /// If this flag is set to `yes`, ssh(1) will additionally check the host
    /// IP address in the known_hosts file.
    ///
    /// This allows ssh to detect if a host key changed due to DNS spoofing. If
    /// the option is set to `no`, the check will not be executed. The default
    /// is `yes`.
    CheckHostIP,

    /// Specifies the cipher to use for encrypting the session in protocol
    /// version 1.
    ///
    /// Currently, `blowfish`, `3des`, and `des` are supported. `des` is only
    /// supported in the ssh(1) client for interoperability with legacy protocol
    /// 1 implementations that do not support the `3des` cipher. Its use is
    /// strongly discouraged due to cryptographic weaknesses. The default is
    /// `3des`.
    Cipher,

    /// Specifies the ciphers allowed for protocol version 2 in order of
    /// preference.
    ///
    /// Multiple ciphers must be comma-separated. The supported ciphers are
    /// `3des-cbc`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, `aes128-ctr`,
    /// `aes192-ctr`, `aes256-ctr`, `arcfour128`, `arcfour256`, `arcfour`,
    /// `blowfish-cbc`, and `cast128-cbc`. The default is:
    ///
    /// ```text
    /// aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,
    /// aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,
    /// aes256-cbc,arcfour
    /// ```
    Ciphers,

    /// Specifies that all local, remote, and dynamic port forwardings specified
    /// in the configuration files or on the command line be cleared.
    ///
    /// This option is primarily useful when used from the ssh(1) command line
    /// to clear port forwardings set in configuration files, and is
    /// automatically set by scp(1) and sftp(1). The argument must be `yes`
    /// or `no`. The default is `no`.
    ClearAllForwardings,

    /// Specifies whether to use compression.
    ///
    /// The argument must be `yes` or `no`. The default is `no`.
    Compression,

    /// Specifies the compression level to use if compression is enabled.
    ///
    /// The argument must be an integer from 1 (fast) to 9 (slow, best). The
    /// default level is 6, which is good for most applications. The meaning
    /// of the values is the same as in gzip(1). Note that this option
    /// applies to protocol version 1 only.
    CompressionLevel,

    /// Specifies the number of tries (one per second) to make before exiting.
    ///
    /// The argument must be an integer. This may be useful in scripts if the
    /// connection sometimes fails. The default is 1.
    ConnectionAttempts,

    /// Specifies the timeout (in seconds) used when connecting to the SSH
    /// server, instead of using the default system TCP timeout.
    ///
    /// This value is used only when the target is down or really unreachable,
    /// not when it refuses the connection.
    ConnectTimeout,

    /// Enables the sharing of multiple sessions over a single network
    /// connection.
    ///
    /// When set to `yes`, ssh(1) will listen for connections on a control
    /// socket specified using the `ControlPath` argument. Additional sessions
    /// can connect to this socket using the same `ControlPath` with
    /// `ControlMaster` set to `no` (the default). These sessions will try to
    /// reuse the master instance's network connection rather than initiating
    /// new ones, but will fall back to connecting normally if the control
    /// socket does not exist, or is not listening.
    ///
    /// Setting this to `ask` will cause ssh to listen for control
    /// connections, but require confirmation using the SSH_ASKPASS program
    /// before they are accepted (see ssh-add(1) for details). If the
    /// `ControlPath` cannot be opened, ssh will continue without connecting to
    /// a master instance.
    ///
    /// X11 and ssh-agent(1) forwarding is supported over these multiplexed
    /// connections, however the display and agent forwarded will be the one
    /// belonging to the master connection i.e. it is not possible to forward
    /// multiple displays or agents.
    ///
    /// Two additional options allow for opportunistic multiplexing: try to use
    /// a master connection but fall back to creating a new one if one does not
    /// already exist. These options are: `auto` and `autoask`. The latter
    /// requires confirmation like the `ask` option.
    ControlMaster,

    /// Specify the path to the control socket used for connection sharing as
    /// described in the `ControlMaster` section above or the string `none` to
    /// disable connection sharing.
    ///
    /// In the path, `%l` will be substituted by the local host name, `%h` will
    /// be substituted by the target host name, `%p` the port, and `%r` by
    /// the remote login username. It is recommended that any `ControlPath`
    /// used for opportunistic connection sharing include at least `%h`, `%p`,
    /// and `%r. This ensures that shared connections are uniquely identified.
    ControlPath,

    /// Specifies that a TCP port on the local machine be forwarded over the
    /// secure channel, and the application protocol is then used to determine
    /// where to connect to from the remote machine.
    ///
    /// The argument must be `[bind_address:]port`. IPv6 addresses can be
    /// specified by enclosing addresses in square brackets or by using an
    /// alternative syntax: `[bind_address/]port`. By default, the local port is
    /// bound in accordance with the `GatewayPorts` setting. However, an
    /// explicit bind_address may be used to bind the connection to a specific
    /// address. The bind_address of `localhost` indicates that the listening
    /// port be bound for local use only, while an empty address or `*`
    /// indicates that the port should be available from all interfaces.
    ///
    /// Currently the `SOCKS4` and `SOCKS5` protocols are supported, and ssh(1)
    /// will act as a `SOCKS` server. Multiple forwardings may be specified,
    /// and additional forwardings can be given on the command line. Only
    /// the superuser can forward privileged ports.
    DynamicForward,

    /// Setting this option to `yes` in the global client configuration file
    /// `/etc/ssh/ssh_config` enables the use of the helper program
    /// ssh-keysign(8) during `HostbasedAuthentication`.
    ///
    /// The argument must be `yes` or `no`. The default is `no`. This option
    /// should be placed in the non-hostspecific section. See ssh-keysign(8)
    /// for more information.
    EnableSSHKeysign,

    /// Sets the escape character (default: '~').
    ///
    /// The escape character can also be set on the command line. The argument
    /// should be a single character, '^' followed by a letter, or `none` to
    /// disable the escape character entirely (making the connection transparent
    /// for binary data).
    EscapeChar,

    /// Specifies whether ssh(1) should terminate the connection if it cannot
    /// set up all requested dynamic, tunnel, local, and remote port
    /// forwardings.
    ///
    /// The argument must be `yes` or `no`. The default is `no`.
    ExitOnForwardFailure,

    /// Specifies whether the connection to the authentication agent (if any)
    /// will be forwarded to the remote machine.
    ///
    /// The argument must be `yes` or `no`. The default is `no`.
    ///
    /// Agent forwarding should be enabled with caution. Users with the ability
    /// to bypass file permissions on the remote host (for the agent's
    /// Unix-domain socket) can access the local agent through the forwarded
    /// connection. An attacker cannot obtain key material from the agent,
    /// however they can perform operations on the keys that enable them to
    /// authenticate using the identities loaded into the agent.
    ForwardAgent,

    /// Specifies whether X11 connections will be automatically redirected over
    /// the secure channel and DISPLAY set.
    ///
    /// The argument must be `yes` or `no`. The default is `no`.
    ///
    /// X11 forwarding should be enabled with caution. Users with the ability to
    /// bypass file permissions on the remote host (for the user's X11
    /// authorization database) can access the local X11 display through the
    /// forwarded connection. An attacker may then be able to perform activities
    /// such as keystroke monitoring if the ForwardX11Trusted option is also
    /// enabled.
    ForwardX11,

    /// If this option is set to `yes`, remote X11 clients will have full
    /// access to the original X11 display.
    ///
    /// If this option is set to `no`, remote X11 clients will be considered
    /// untrusted and prevented from stealing or tampering with data belonging
    /// to trusted X11 clients. Furthermore, the xauth(1) token used for the
    /// session will be set to expire after 20 minutes. Remote clients will be
    /// refused access after this time.
    ///
    /// The default is `no`.
    ///
    /// See the `X11 SECURITY` extension specification for full details on the
    /// restrictions imposed on untrusted clients.
    ForwardX11Trusted,

    /// Specifies whether remote hosts are allowed to connect to local forwarded
    /// ports.
    ///
    /// By default, ssh(1) binds local port forwardings to the loopback address.
    /// This prevents other remote hosts from connecting to forwarded ports.
    /// `GatewayPorts` can be used to specify that ssh should bind local
    /// port forwardings to the wildcard address, thus allowing remote hosts to
    /// connect to forwarded ports. The argument must be `yes` or `no`. The
    /// default is `no`.
    GatewayPorts,

    /// Specifies a file to use for the global host key database instead of
    /// `/etc/ssh/ssh_known_hosts`.
    GlobalKnownHostsFile,

    /// Specifies whether user authentication based on GSSAPI is allowed.
    ///
    /// The default is `no`. Note that this option applies to protocol version 2
    /// only.
    GSSAPIAuthentication,

    /// Specifies whether key exchange based on GSSAPI may be used.
    ///
    /// When using GSSAPI key exchange the server need not have a host key. The
    /// default is `no`. Note that this option applies to protocol version 2
    /// only.
    GSSAPIKeyExchange,

    /// If set, specifies the GSSAPI client identity that ssh should use when
    /// connecting to the server.
    ///
    /// The default is unset, which means that the default identity will be
    /// used.
    GSSAPIClientIdentity,

    /// Forward (delegate) credentials to the server.
    ///
    /// The default is `no`. Note that this option applies to protocol version 2
    /// connections using GSSAPI.
    GSSAPIDelegateCredentials,

    /// If set to `yes` then renewal of the client's GSSAPI credentials will
    /// force the rekeying of the ssh connection.
    ///
    /// With a compatible server, this can delegate the renewed credentials to a
    /// session on the server. The default is `no`.
    GSSAPIRenewalForcesRekey,

    /// Set to `yes` to indicate that the DNS is trusted to securely
    /// canonicalize` the name of the host being connected to.
    ///
    /// If `no`, the hostname entered on the command line will be passed
    /// untouched to the GSSAPI library. The default is `no`. This option
    /// only applies to protocol version 2 connections using GSSAPI.
    GSSAPITrustDns,

    /// Indicates that ssh(1) should hash host names and addresses when they are
    /// added to `~/.ssh/known_hosts`.
    ///
    /// These hashed names may be used normally by ssh(1) and sshd(8), but they
    /// do not reveal identifying information should the file's contents be
    /// disclosed. The default is `no`. Note that existing names and addresses
    /// in known hosts files will not be converted automatically, but may be
    /// manually hashed using ssh-keygen(1).
    HashKnownHosts,

    /// Specifies whether to try rhosts based authentication with public key
    /// authentication.
    ///
    /// The argument must be `yes` or `no`. The default is `no`. This option
    /// applies to protocol version 2 only and is similar to
    /// `RhostsRSAAuthentication`.
    HostbasedAuthentication,

    /// Specifies the protocol version 2 host key algorithms that the client
    /// wants to use in order of preference.
    ///
    /// The default for this option is: `ssh-rsa,ssh-dss`.
    HostKeyAlgorithms,

    /// Specifies an alias that should be used instead of the real host name
    /// when looking up or saving the host key in the host key database files.
    ///
    /// This option is useful for tunneling SSH connections or for multiple
    /// servers running on a single host.
    HostKeyAlias,

    /// Specifies the real host name to log into.
    ///
    /// This can be used to specify nicknames or abbreviations for hosts. The
    /// default is the name given on the command line. Numeric IP addresses
    /// are also permitted (both on the command line and in `HostName`
    /// specifications).
    HostName,

    /// Specifies that ssh(1) should only use the authentication identity files
    /// configured in the ssh_config files, even if ssh-agent(1) offers more
    /// identities.
    ///
    /// The argument to this keyword must be `yes` or `no`. This option is
    /// intended for situations where `ssh-agent` offers many different
    /// identities. The default is `no`.
    IdentitiesOnly,

    /// Specifies a file from which the user's RSA or DSA authentication
    /// identity is read.
    ///
    /// The default is `~/.ssh/identity` for protocol version 1, and
    /// `~/.ssh/id_rsa` and `~/.ssh/id_dsa` for protocol version 2.
    /// Additionally, any identities represented by the authentication agent
    /// will be used for authentication.
    ///
    /// The file name may use the tilde syntax to refer to a user's home
    /// directory or one of the following escape characters: `%d` (local user's
    /// home directory), `%u` (local user name), `%l` (local host name), `%h`
    /// (remote host name) or `%r` (remote user name).
    ///
    /// It is possible to have multiple identity files specified in
    /// configuration files; all these identities will be tried in sequence.
    IdentityFile,

    /// Specifies whether to use keyboard-interactive authentication.
    ///
    /// The argument to this keyword must be `yes` or `no`. The default is
    /// `yes`.
    KbdInteractiveAuthentication,

    /// Specifies the list of methods to use in keyboard-interactive
    /// authentication.
    ///
    /// Multiple method names must be comma-separated. The default is to use the
    /// server specified list. The methods available vary depending on what
    /// the server supports. For an OpenSSH server, it may be zero or more
    /// of: `bsdauth`, `pam`, and `skey`.
    KbdInteractiveDevices,

    /// Specifies a command to execute on the local machine after successfully
    /// connecting to the server.
    ///
    /// The command string extends to the end of the line, and is executed with
    /// the user's shell. The following escape character substitutions will
    /// be performed:
    ///
    /// * `%d` (local user's home directory)
    /// * `%h` (remote host name)
    /// * `%l` (local host name)
    /// * `%n` (host name as provided on the command line)
    /// * `%p` (remote port)
    /// * `%r` (remote user name)
    /// * `%u` (local user name)
    ///
    /// This directive is ignored unless `PermitLocalCommand` has been enabled.
    LocalCommand,

    /// Specifies that a TCP port on the local machine be forwarded over the
    /// secure channel to the specified host and port from the remote machine.
    ///
    /// The first argument must be `[bind_address:]port` and the second
    /// argument must be `host:hostport`. IPv6 addresses can be specified by
    /// enclosing addresses in square brackets or by using an alternative
    /// syntax: `[bind_address/]port` and `host/hostport`. Multiple
    /// forwardings may be specified, and additional forwardings can be given on
    /// the command line. Only the superuser can forward privileged ports. By
    /// default, the local port is bound in accordance with the `GatewayPorts`
    /// setting. However, an explicit bind_address may be used to bind the
    /// connection to a specific address. The bind_address of `localhost`
    /// indicates that the listening port be bound for local use only, while an
    /// empty address or `*` indicates that the port should be available from
    /// all interfaces.
    LocalForward,

    /// Gives the verbosity level that is used when logging messages from
    /// ssh(1).
    ///
    /// The possible values are: `QUIET`, `FATAL`, `ERROR`, `INFO`, `VERBOSE`,
    /// `DEBUG`, `DEBUG1`, `DEBUG2`, and `DEBUG3`. The default is `INFO`.
    /// `DEBUG` and `DEBUG1` are equivalent. `DEBUG2` and `DEBUG3` each
    /// specify higher levels of verbose output.
    LogLevel,

    /// Specifies the MAC (message authentication code) algorithms in order of
    /// preference.
    ///
    /// The MAC algorithm is used in protocol version 2 for data integrity
    /// protection. Multiple algorithms must be comma-separated. The default
    /// is:
    ///
    /// ```text
    /// hmac-md5,hmac-sha1,umac-64@openssh.com,
    /// hmac-ripemd160,hmac-sha1-96,hmac-md5-96
    /// ```
    MACs,

    /// This option can be used if the home directory is shared across machines.
    ///
    /// In this case localhost will refer to a different machine on each of the
    /// machines and the user will get many warnings about changed host keys.
    /// However, this option disables host authentication for localhost. The
    /// argument to this keyword must be `yes` or `no`. The default is to
    /// check the host key for localhost.
    NoHostAuthenticationForLocalhost,

    /// Specifies the number of password prompts before giving up.
    ///
    /// The argument to this keyword must be an integer. The default is 3.
    NumberOfPasswordPrompts,

    /// Specifies whether to use password authentication.
    ///
    /// The argument to this keyword must be `yes` or `no`. The default is
    /// `yes`.
    PasswordAuthentication,

    /// Allow local command execution via the LocalCommand option or using the
    /// `!command` escape sequence in ssh(1).
    ///
    /// The argument must be `yes` or `no`. The default is `no`.
    PermitLocalCommand,

    /// Specifies the port number to connect on the remote host.
    ///
    /// The default is 22.
    Port,

    /// Specifies the order in which the client should try protocol 2
    /// authentication methods.
    ///
    /// This allows a client to prefer one method (e.g. keyboard-interactive)
    /// over another method (e.g. password). The default for this option is:
    /// `gssapi-with-mic, hostbased, publickey, keyboard-interactive, password`.
    PreferredAuthentications,

    /// Specifies the protocol versions ssh(1) should support in order of
    /// preference.
    ///
    /// The possible values are '1' and '2'. Multiple versions must be
    /// comma-separated. The default is `2,1`. This means that ssh tries
    /// version 2 and falls back to version 1 if version 2 is not available.
    Protocol,

    /// Specifies the command to use to connect to the server.
    ///
    /// The command string extends to the end of the line, and is executed with
    /// the user's shell. In the command string, `%h` will be substituted by
    /// the host name to connect and `%p` by the port. The command can be
    /// basically anything, and should read from its standard input and
    /// write to its standard output. It should eventually connect an
    /// sshd(8) server running on some machine, or execute sshd -i
    /// somewhere. Host key management will be done using the HostName of
    /// the host being connected (defaulting to the name typed by the user).
    /// Setting the command to `none` disables this option entirely. Note
    /// that [`CheckHostIP`][Self::CheckHostIP] is not available for connects
    /// with a proxy command.
    ///
    /// This directive is useful in conjunction with nc(1) and its proxy
    /// support. For example, the following directive would connect via an HTTP
    /// proxy at 192.0.2.0:
    ///
    /// ```text
    /// ProxyCommand /usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p
    /// ```
    ProxyCommand,

    /// Specifies whether to try public key authentication.
    ///
    /// The argument to this keyword must be `yes` or `no`. The default is
    /// `yes`. This option applies to protocol version 2 only.
    PubkeyAuthentication,

    /// Specifies the maximum amount of data that may be transmitted before the
    /// session key is renegotiated.
    ///
    /// The argument is the number of bytes, with an optional suffix of 'K',
    /// 'M', or 'G' to indicate Kilobytes, Megabytes, or Gigabytes,
    /// respectively. The default is between '1G' and '4G', depending on the
    /// cipher. This option applies to protocol version 2 only.
    RekeyLimit,

    /// Specifies that a TCP port on the remote machine be forwarded over the
    /// secure channel to the specified host and port from the local machine.
    ///
    /// The first argument must be `[bind_address:]port` and the second
    /// argument must be `host:hostport`. IPv6 addresses can be specified by
    /// enclosing addresses in square brackets or by using an alternative
    /// syntax: `[bind_address/]port` and `host/hostport`. Multiple forwardings
    /// may be specified, and additional forwardings can be given on the command
    /// line. Privileged ports can be forwarded only when logging in as root on
    /// the remote machine.
    ///
    /// If the port argument is '0', the listen port will be dynamically
    /// allocated on the server and reported to the client at run time.
    ///
    /// If the bind_address is not specified, the default is to only bind to
    /// loopback addresses. If the bind_address is `*` or an empty string, then
    /// the forwarding is requested to listen on all interfaces. Specifying a
    /// remote bind_address will only succeed if the server's GatewayPorts
    /// option is enabled (see sshd_config(5)).
    RemoteForward,

    /// Specifies whether to try rhosts based authentication with RSA host
    /// authentication.
    ///
    /// The argument must be `yes` or `no`. The default is `no`. This option
    /// applies to protocol version 1 only and requires ssh(1) to be setuid
    /// root.
    RhostsRSAAuthentication,

    /// Specifies whether to try RSA authentication.
    ///
    /// The argument to this keyword must be `yes` or `no`. RSA authentication
    /// will only be attempted if the identity file exists, or an authentication
    /// agent is running. The default is `yes`. Note that this option
    /// applies to protocol version 1 only.
    RSAAuthentication,

    /// Specifies what variables from the local environ(7) should be sent to the
    /// server.
    ///
    /// Note that environment passing is only supported for protocol 2. The
    /// server must also support it, and the server must be configured to
    /// accept these environment variables. Refer to AcceptEnv in sshd_config(5)
    /// for how to configure the server. Variables are specified by name, which
    /// may contain wildcard characters. Multiple environment variables may be
    /// separated by whitespace or spread across multiple SendEnv directives.
    /// The default is not to send any environment variables.
    ///
    /// See [Patterns](index.html#patterns) for more information on patterns.
    SendEnv,

    /// Sets the number of server alive messages (see below) which may be sent
    /// without ssh(1) receiving any messages back from the server.
    ///
    /// If this threshold is reached while server alive messages are being sent,
    /// ssh will disconnect from the server, terminating the session. It is
    /// important to note that the use of server alive messages is very
    /// different from `TCPKeepAlive` (below). The server alive messages are
    /// sent through the encrypted channel and therefore will not be
    /// spoofable. The TCP keepalive option enabled by `TCPKeepAlive` is
    /// spoofable. The server alive mechanism is valuable when the client or
    /// server depend on knowing when a connection has become inactive.
    ///
    /// The default value is 3. If, for example, `ServerAliveInterval` (see
    /// below) is set to 15 and `ServerAliveCountMax` is left at the default,
    /// if the server becomes unresponsive, ssh will disconnect after
    /// approximately 45 seconds. This option applies to protocol version 2
    /// only.
    ServerAliveCountMax,

    /// Sets a timeout interval in seconds after which if no data has been
    /// received from the server, ssh(1) will send a message through the
    /// encrypted channel to request a response from the server.
    ///
    /// The default is 0, indicating that these messages will not be sent to the
    /// server. This option applies to protocol version 2 only.
    ServerAliveInterval,

    /// Specifies which smartcard device to use.
    ///
    /// The argument to this keyword is the device ssh(1) should use to
    /// communicate with a smartcard used for storing the user's private RSA
    /// key. By default, no device is specified and smartcard support is not
    /// activated.
    SmartcardDevice,

    /// If this flag is set to `yes`, ssh(1) will never automatically add host
    /// keys to the `~/.ssh/known_hosts` file, and refuses to connect to hosts
    /// whose host key has changed.
    ///
    /// This provides maximum protection against trojan horse attacks, though it
    /// can be annoying when the `/etc/ssh/ssh_known_hosts` file is poorly
    /// maintained or when connections to new hosts are frequently made.
    /// This option forces the user to manually add all new hosts. If this
    /// flag is set to `no`, ssh will automatically add new host keys to the
    /// user known hosts files. If this flag is set to `ask`, new host keys
    /// will be added to the user known host files only after the user has
    /// confirmed that is what they really want to do, and ssh will refuse
    /// to connect to hosts whose host key has changed. The host keys of
    /// known hosts will be verified automatically in all cases. The
    /// argument must be `yes`, `no`, or `ask`. The default is `ask`.
    StrictHostKeyChecking,

    /// Specifies whether the system should send TCP keepalive messages to the
    /// other side.
    ///
    /// If they are sent, death of the connection or crash of one of the
    /// machines will be properly noticed. However, this means that
    /// connections will die if the route is down temporarily, and some people
    /// find it annoying.
    ///
    /// The default is `yes` (to send TCP keepalive messages), and the client
    /// will notice if the network goes down or the remote host dies. This is
    /// important in scripts, and many users want it too.
    ///
    /// To disable TCP keepalive messages, the value should be set to `no`.
    TCPKeepAlive,

    /// Request tun(4) device forwarding between the client and the server.
    ///
    /// The argument must be `yes`, `point-to-point` (layer 3), `ethernet`
    /// (layer 2), or `no`. Specifying `yes` requests the default tunnel
    /// mode, which is `point-to-point`. The default is `no`.
    Tunnel,

    /// Specifies the tun(4) devices to open on the client (`local_tun`) and the
    /// server (`remote_tun`).
    ///
    /// The argument must be `local_tun[:remote_tun]`. The devices may be
    /// specified by numerical ID or the keyword `any`, which uses the next
    /// available tunnel device. If remote_tun is not specified, it defaults to
    /// `any`. The default is `any:any`.
    TunnelDevice,

    /// Specifies whether to use a privileged port for outgoing connections.
    ///
    /// The argument must be `yes` or `no`. The default is `no`. If set to
    /// `yes`, ssh(1) must be setuid root. Note that this option must be set
    /// to `yes` for `RhostsRSAAuthentication` with older servers.
    UsePrivilegedPort,

    /// Specifies the user to log in as.
    ///
    /// This can be useful when a different user name is used on different
    /// machines. This saves the trouble of having to remember to give the
    /// user name on the command line.
    User,

    /// Specifies a file to use for the user host key database instead of
    /// `~/.ssh/known_hosts`.
    UserKnownHostsFile,

    /// Specifies whether to verify the remote key using DNS and SSHFP resource
    /// records.
    ///
    /// If this option is set to `yes`, the client will implicitly trust keys
    /// that match a secure fingerprint from DNS. Insecure fingerprints will
    /// be handled as if this option was set to `ask`. If this option is set
    /// to `ask`, information on fingerprint match will be displayed, but
    /// the user will still need to confirm new host keys according to the
    /// StrictHostKeyChecking option. The argument must be `yes`, `no`, or
    /// `ask`. The default is `no`. Note that this option applies to
    /// protocol version 2 only.
    ///
    /// See also VERIFYING HOST KEYS in ssh(1).
    VerifyHostKeyDNS,

    /// If this flag is set to `yes`, an ASCII art representation of the
    /// remote host key fingerprint is printed in addition to the hex
    /// fingerprint string at login and for unknown host keys.
    ///
    /// If this flag is set to `no`, no fingerprint strings are printed at login
    /// and only the hex fingerprint string will be printed for unknown host
    /// keys. The default is `no`.
    VisualHostKey,

    /// Specifies the full pathname of the xauth(1) program.
    ///
    /// The default is `/usr/bin/xauth`.
    XAuthLocation,
}

impl FromStr for SshOptionKey {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("host") {
            Ok(Self::Host)
        } else if s.eq_ignore_ascii_case("addressfamily") {
            Ok(Self::AddressFamily)
        } else if s.eq_ignore_ascii_case("batchmode") {
            Ok(Self::BatchMode)
        } else if s.eq_ignore_ascii_case("bindaddress") {
            Ok(Self::BindAddress)
        } else if s.eq_ignore_ascii_case("challengeresponseauthentication") {
            Ok(Self::ChallengeResponseAuthentication)
        } else if s.eq_ignore_ascii_case("checkhostip") {
            Ok(Self::CheckHostIP)
        } else if s.eq_ignore_ascii_case("cipher") {
            Ok(Self::Cipher)
        } else if s.eq_ignore_ascii_case("ciphers") {
            Ok(Self::Ciphers)
        } else if s.eq_ignore_ascii_case("clearallforwardings") {
            Ok(Self::ClearAllForwardings)
        } else if s.eq_ignore_ascii_case("compression") {
            Ok(Self::Compression)
        } else if s.eq_ignore_ascii_case("compressionlevel") {
            Ok(Self::CompressionLevel)
        } else if s.eq_ignore_ascii_case("connectionattempts") {
            Ok(Self::ConnectionAttempts)
        } else if s.eq_ignore_ascii_case("connecttimeout") {
            Ok(Self::ConnectTimeout)
        } else if s.eq_ignore_ascii_case("controlmaster") {
            Ok(Self::ControlMaster)
        } else if s.eq_ignore_ascii_case("controlpath") {
            Ok(Self::ControlPath)
        } else if s.eq_ignore_ascii_case("dynamicforward") {
            Ok(Self::DynamicForward)
        } else if s.eq_ignore_ascii_case("enablesshkeysign") {
            Ok(Self::EnableSSHKeysign)
        } else if s.eq_ignore_ascii_case("escapechar") {
            Ok(Self::EscapeChar)
        } else if s.eq_ignore_ascii_case("exitonforwardfailure") {
            Ok(Self::ExitOnForwardFailure)
        } else if s.eq_ignore_ascii_case("forwardagent") {
            Ok(Self::ForwardAgent)
        } else if s.eq_ignore_ascii_case("forwardx11") {
            Ok(Self::ForwardX11)
        } else if s.eq_ignore_ascii_case("forwardx11trusted") {
            Ok(Self::ForwardX11Trusted)
        } else if s.eq_ignore_ascii_case("gatewayports") {
            Ok(Self::GatewayPorts)
        } else if s.eq_ignore_ascii_case("globalknownhostsfile") {
            Ok(Self::GlobalKnownHostsFile)
        } else if s.eq_ignore_ascii_case("gssapiauthentication") {
            Ok(Self::GSSAPIAuthentication)
        } else if s.eq_ignore_ascii_case("gssapikeyexchange") {
            Ok(Self::GSSAPIKeyExchange)
        } else if s.eq_ignore_ascii_case("gssapiclientidentity") {
            Ok(Self::GSSAPIClientIdentity)
        } else if s.eq_ignore_ascii_case("gssapidelegatecredentials") {
            Ok(Self::GSSAPIDelegateCredentials)
        } else if s.eq_ignore_ascii_case("gssapirenewalforcesrekey") {
            Ok(Self::GSSAPIRenewalForcesRekey)
        } else if s.eq_ignore_ascii_case("gssapitrustdns") {
            Ok(Self::GSSAPITrustDns)
        } else if s.eq_ignore_ascii_case("hashknownhosts") {
            Ok(Self::HashKnownHosts)
        } else if s.eq_ignore_ascii_case("hostbasedauthentication") {
            Ok(Self::HostbasedAuthentication)
        } else if s.eq_ignore_ascii_case("hostkeyalgorithms") {
            Ok(Self::HostKeyAlgorithms)
        } else if s.eq_ignore_ascii_case("hostkeyalias") {
            Ok(Self::HostKeyAlias)
        } else if s.eq_ignore_ascii_case("hostname") {
            Ok(Self::HostName)
        } else if s.eq_ignore_ascii_case("identitiesonly") {
            Ok(Self::IdentitiesOnly)
        } else if s.eq_ignore_ascii_case("identityfile") {
            Ok(Self::IdentityFile)
        } else if s.eq_ignore_ascii_case("kbdinteractiveauthentication") {
            Ok(Self::KbdInteractiveAuthentication)
        } else if s.eq_ignore_ascii_case("kbdinteractivedevices") {
            Ok(Self::KbdInteractiveDevices)
        } else if s.eq_ignore_ascii_case("localcommand") {
            Ok(Self::LocalCommand)
        } else if s.eq_ignore_ascii_case("localforward") {
            Ok(Self::LocalForward)
        } else if s.eq_ignore_ascii_case("loglevel") {
            Ok(Self::LogLevel)
        } else if s.eq_ignore_ascii_case("macs") {
            Ok(Self::MACs)
        } else if s.eq_ignore_ascii_case("nohostauthenticationforlocalhost") {
            Ok(Self::NoHostAuthenticationForLocalhost)
        } else if s.eq_ignore_ascii_case("numberofpasswordprompts") {
            Ok(Self::NumberOfPasswordPrompts)
        } else if s.eq_ignore_ascii_case("passwordauthentication") {
            Ok(Self::PasswordAuthentication)
        } else if s.eq_ignore_ascii_case("permitlocalcommand") {
            Ok(Self::PermitLocalCommand)
        } else if s.eq_ignore_ascii_case("port") {
            Ok(Self::Port)
        } else if s.eq_ignore_ascii_case("preferredauthentications") {
            Ok(Self::PreferredAuthentications)
        } else if s.eq_ignore_ascii_case("protocol") {
            Ok(Self::Protocol)
        } else if s.eq_ignore_ascii_case("proxycommand") {
            Ok(Self::ProxyCommand)
        } else if s.eq_ignore_ascii_case("pubkeyauthentication") {
            Ok(Self::PubkeyAuthentication)
        } else if s.eq_ignore_ascii_case("rekeylimit") {
            Ok(Self::RekeyLimit)
        } else if s.eq_ignore_ascii_case("remoteforward") {
            Ok(Self::RemoteForward)
        } else if s.eq_ignore_ascii_case("rhostsrsaauthentication") {
            Ok(Self::RhostsRSAAuthentication)
        } else if s.eq_ignore_ascii_case("rsaauthentication") {
            Ok(Self::RSAAuthentication)
        } else if s.eq_ignore_ascii_case("sendenv") {
            Ok(Self::SendEnv)
        } else if s.eq_ignore_ascii_case("serveralivecountmax") {
            Ok(Self::ServerAliveCountMax)
        } else if s.eq_ignore_ascii_case("serveraliveinterval") {
            Ok(Self::ServerAliveInterval)
        } else if s.eq_ignore_ascii_case("smartcarddevice") {
            Ok(Self::SmartcardDevice)
        } else if s.eq_ignore_ascii_case("stricthostkeychecking") {
            Ok(Self::StrictHostKeyChecking)
        } else if s.eq_ignore_ascii_case("tcpkeepalive") {
            Ok(Self::TCPKeepAlive)
        } else if s.eq_ignore_ascii_case("tunnel") {
            Ok(Self::Tunnel)
        } else if s.eq_ignore_ascii_case("tunneldevice") {
            Ok(Self::TunnelDevice)
        } else if s.eq_ignore_ascii_case("useprivilegedport") {
            Ok(Self::UsePrivilegedPort)
        } else if s.eq_ignore_ascii_case("user") {
            Ok(Self::User)
        } else if s.eq_ignore_ascii_case("userknownhostsfile") {
            Ok(Self::UserKnownHostsFile)
        } else if s.eq_ignore_ascii_case("verifyhostkeydns") {
            Ok(Self::VerifyHostKeyDNS)
        } else if s.eq_ignore_ascii_case("visualhostkey") {
            Ok(Self::VisualHostKey)
        } else if s.eq_ignore_ascii_case("xauthlocation") {
            Ok(Self::XAuthLocation)
        } else {
            Err(ConfigError::SshOptionUnknown { key: s.to_string() })
        }
    }
}

impl fmt::Display for SshOptionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Host => write!(f, "Host"),
            Self::AddressFamily => write!(f, "AddressFamily"),
            Self::BatchMode => write!(f, "BatchMode"),
            Self::BindAddress => write!(f, "BindAddress"),
            Self::ChallengeResponseAuthentication => write!(f, "ChallengeResponseAuthentication"),
            Self::CheckHostIP => write!(f, "CheckHostIP"),
            Self::Cipher => write!(f, "Cipher"),
            Self::Ciphers => write!(f, "Ciphers"),
            Self::ClearAllForwardings => write!(f, "ClearAllForwardings"),
            Self::Compression => write!(f, "Compression"),
            Self::CompressionLevel => write!(f, "CompressionLevel"),
            Self::ConnectionAttempts => write!(f, "ConnectionAttempts"),
            Self::ConnectTimeout => write!(f, "ConnectTimeout"),
            Self::ControlMaster => write!(f, "ControlMaster"),
            Self::ControlPath => write!(f, "ControlPath"),
            Self::DynamicForward => write!(f, "DynamicForward"),
            Self::EnableSSHKeysign => write!(f, "EnableSSHKeysign"),
            Self::EscapeChar => write!(f, "EscapeChar"),
            Self::ExitOnForwardFailure => write!(f, "ExitOnForwardFailure"),
            Self::ForwardAgent => write!(f, "ForwardAgent"),
            Self::ForwardX11 => write!(f, "ForwardX11"),
            Self::ForwardX11Trusted => write!(f, "ForwardX11Trusted"),
            Self::GatewayPorts => write!(f, "GatewayPorts"),
            Self::GlobalKnownHostsFile => write!(f, "GlobalKnownHostsFile"),
            Self::GSSAPIAuthentication => write!(f, "GSSAPIAuthentication"),
            Self::GSSAPIKeyExchange => write!(f, "GSSAPIKeyExchange"),
            Self::GSSAPIClientIdentity => write!(f, "GSSAPIClientIdentity"),
            Self::GSSAPIDelegateCredentials => write!(f, "GSSAPIDelegateCredentials"),
            Self::GSSAPIRenewalForcesRekey => write!(f, "GSSAPIRenewalForcesRekey"),
            Self::GSSAPITrustDns => write!(f, "GSSAPITrustDns"),
            Self::HashKnownHosts => write!(f, "HashKnownHosts"),
            Self::HostbasedAuthentication => write!(f, "HostbasedAuthentication"),
            Self::HostKeyAlgorithms => write!(f, "HostKeyAlgorithms"),
            Self::HostKeyAlias => write!(f, "HostKeyAlias"),
            Self::HostName => write!(f, "HostName"),
            Self::IdentitiesOnly => write!(f, "IdentitiesOnly"),
            Self::IdentityFile => write!(f, "IdentityFile"),
            Self::KbdInteractiveAuthentication => write!(f, "KbdInteractiveAuthentication"),
            Self::KbdInteractiveDevices => write!(f, "KbdInteractiveDevices"),
            Self::LocalCommand => write!(f, "LocalCommand"),
            Self::LocalForward => write!(f, "LocalForward"),
            Self::LogLevel => write!(f, "LogLevel"),
            Self::MACs => write!(f, "MACs"),
            Self::NoHostAuthenticationForLocalhost => write!(f, "NoHostAuthenticationForLocalhost"),
            Self::NumberOfPasswordPrompts => write!(f, "NumberOfPasswordPrompts"),
            Self::PasswordAuthentication => write!(f, "PasswordAuthentication"),
            Self::PermitLocalCommand => write!(f, "PermitLocalCommand"),
            Self::Port => write!(f, "Port"),
            Self::PreferredAuthentications => write!(f, "PreferredAuthentications"),
            Self::Protocol => write!(f, "Protocol"),
            Self::ProxyCommand => write!(f, "ProxyCommand"),
            Self::PubkeyAuthentication => write!(f, "PubkeyAuthentication"),
            Self::RekeyLimit => write!(f, "RekeyLimit"),
            Self::RemoteForward => write!(f, "RemoteForward"),
            Self::RhostsRSAAuthentication => write!(f, "RhostsRSAAuthentication"),
            Self::RSAAuthentication => write!(f, "RSAAuthentication"),
            Self::SendEnv => write!(f, "SendEnv"),
            Self::ServerAliveCountMax => write!(f, "ServerAliveCountMax"),
            Self::ServerAliveInterval => write!(f, "ServerAliveInterval"),
            Self::SmartcardDevice => write!(f, "SmartcardDevice"),
            Self::StrictHostKeyChecking => write!(f, "StrictHostKeyChecking"),
            Self::TCPKeepAlive => write!(f, "TCPKeepAlive"),
            Self::Tunnel => write!(f, "Tunnel"),
            Self::TunnelDevice => write!(f, "TunnelDevice"),
            Self::UsePrivilegedPort => write!(f, "UsePrivilegedPort"),
            Self::User => write!(f, "User"),
            Self::UserKnownHostsFile => write!(f, "UserKnownHostsFile"),
            Self::VerifyHostKeyDNS => write!(f, "VerifyHostKeyDNS"),
            Self::VisualHostKey => write!(f, "VisualHostKey"),
            Self::XAuthLocation => write!(f, "XAuthLocation"),
        }
    }
}
