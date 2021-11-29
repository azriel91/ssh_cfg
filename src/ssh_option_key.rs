use std::{fmt, str::FromStr};

use crate::ConfigError;

/// SSH option keys inside the SSH configuration file.
///
/// See <https://linux.die.net/man/5/ssh_config>
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SshOptionKey {
    ///     Specifies what environment variables sent by the client will be
    ///     copied into the session's environ(7).  See SendEnv and SetEnv in
    ///     ssh_config(5) for how to configure the client.  The TERM environ-
    ///     ment variable is always accepted whenever the client requests a
    ///     pseudo-terminal as it is required by the protocol.  Variables are
    ///     specified by name, which may contain the wildcard characters `*'
    ///     and `?'.  Multiple environment variables may be separated by
    ///     whitespace or spread across multiple AcceptEnv directives.  Be
    ///     warned that some environment variables could be used to bypass
    ///     restricted user environments.  For this reason, care should be
    ///     taken in the use of this directive.  The default is not to accept
    ///     any environment variables.
    AcceptEnv,

    ///  Specifies whether ssh-agent(1) forwarding is permitted.  The de-
    ///  fault is yes.  Note that disabling agent forwarding does not im-
    ///  prove security unless users are also denied shell access, as they
    ///  can always install their own forwarders.
    AllowAgentForwarding,

    ///    This keyword can be followed by a list of group name patterns,
    ///    separated by spaces.  If specified, login is allowed only for
    ///    users whose primary group or supplementary group list matches one
    ///    of the patterns.  Only group names are valid; a numerical group
    ///    ID is not recognized.  By default, login is allowed for all
    ///    groups.  The allow/deny directives are processed in the following
    ///    order: DenyUsers, AllowUsers, DenyGroups, and finally
    ///    AllowGroups.
    ///    See PATTERNS in ssh_config(5) for more information on patterns.
    AllowGroups,

    /// Specifies whether StreamLocal (Unix-domain socket) forwarding is
    /// permitted.  The available options are yes (the default) or all to
    /// allow StreamLocal forwarding, no to prevent all StreamLocal for-
    /// warding, local to allow local (from the perspective of ssh(1))
    /// forwarding only or remote to allow remote forwarding only.  Note
    /// that disabling StreamLocal forwarding does not improve security
    /// unless users are also denied shell access, as they can always in-
    /// stall their own forwarders.
    AllowStreamLocalForwarding,

    /// Specifies whether TCP forwarding is permitted.  The available op-
    /// tions are yes (the default) or all to allow TCP forwarding, no to
    /// prevent all TCP forwarding, local to allow local (from the per-
    /// spective of ssh(1)) forwarding only or remote to allow remote
    /// forwarding only.  Note that disabling TCP forwarding does not im-
    /// prove security unless users are also denied shell access, as they
    /// can always install their own forwarders.
    AllowTcpForwarding,

    ///      This keyword can be followed by a list of user name patterns,
    ///      separated by spaces.  If specified, login is allowed only for
    ///      user names that match one of the patterns.  Only user names are
    ///      valid; a numerical user ID is not recognized.  By default, login
    ///      is allowed for all users. If the pattern takes the form
    ///      USER@HOST then USER and HOST are separately checked, restricting
    ///      logins to particular users from particular hosts. HOST criteria
    ///      may additionally contain addresses to match in CIDR ad-
    ///      dress/masklen format.  The allow/deny directives are processed in
    ///      the following order: DenyUsers, AllowUsers, DenyGroups, and fi-
    ///      nally AllowGroups.

    ///      See PATTERNS in ssh_config(5) for more information on patterns.
    AllowUsers,

    ///      Specifies the authentication methods that must be successfully
    ///      completed for a user to be granted access.  This option must be
    ///      followed by one or more lists of comma-separated authentication
    ///      method names, or by the single string any to indicate the default
    ///      behaviour of accepting any single authentication method.  If the
    ///      default is overridden, then successful authentication requires
    ///      completion of every method in at least one of these lists.

    ///      For example, "publickey,password publickey,keyboard-interactive"
    ///      would require the user to complete public key authentication,
    ///      followed by either password or keyboard interactive authentica-
    ///      tion.  Only methods that are next in one or more lists are of-
    ///      fered at each stage, so for this example it would not be possible
    ///      to attempt password or keyboard-interactive authentication before
    ///      public key.

    ///      For keyboard interactive authentication it is also possible to
    ///      restrict authentication to a specific device by appending a colon
    ///      followed by the device identifier bsdauth or pam. depending on
    ///      the server configuration. For example,
    ///      "keyboard-interactive:bsdauth" would restrict keyboard interac-
    ///      tive authentication to the bsdauth device.

    ///      If the publickey method is listed more than once, sshd(8) veri-
    ///      fies that keys that have been used successfully are not reused
    ///      for subsequent authentications.  For example,
    ///      "publickey,publickey" requires successful authentication using
    ///      two different public keys.

    ///      Note that each authentication method listed should also be ex-
    ///      plicitly enabled in the configuration.

    ///      The available authentication methods are: "gssapi-with-mic",
    ///      "hostbased", "keyboard-interactive", "none" (used for access to
    ///      password-less accounts when PermitEmptyPasswords is enabled),
    ///      "password" and "publickey".
    AuthenticationMethods,

    ///      Specifies a program to be used to look up the user's public keys.
    ///      The program must be owned by root, not writable by group or oth-
    ///      ers and specified by an absolute path.  Arguments to
    ///      AuthorizedKeysCommand accept the tokens described in the TOKENS
    ///      section.  If no arguments are specified then the username of the
    ///      target user is used.

    ///      The program should produce on standard output zero or more lines
    ///      of authorized_keys output (see AUTHORIZED_KEYS in sshd(8)).  If a
    ///      key supplied by AuthorizedKeysCommand does not successfully au-
    ///      thenticate and authorize the user then public key authentication
    ///      continues using the usual AuthorizedKeysFile files.  By default,
    ///      no AuthorizedKeysCommand is run.
    AuthorizedKeysCommand,

    ///      Specifies the user under whose account the AuthorizedKeysCommand
    ///      is run.  It is recommended to use a dedicated user that has no
    ///      other role on the host than running authorized keys commands.  If
    ///      AuthorizedKeysCommand is specified but AuthorizedKeysCommandUser
    ///      is not, then sshd(8) will refuse to start.
    AuthorizedKeysCommandUser,

    ///      Specifies the file that contains the public keys used for user
    ///      authentication.  The format is described in the AUTHORIZED_KEYS
    ///      FILE FORMAT section of sshd(8).  Arguments to AuthorizedKeysFile
    ///      accept the tokens described in the TOKENS section.  After expan-
    ///      sion, AuthorizedKeysFile is taken to be an absolute path or one
    ///      relative to the user's home directory.  Multiple files may be
    ///      listed, separated by whitespace.  Alternately this option may be
    ///      set to none to skip checking for user keys in files.  The default
    ///      is ".ssh/authorized_keys .ssh/authorized_keys2".
    AuthorizedKeysFile,

    ///      Specifies a program to be used to generate the list of allowed
    ///      certificate principals as per AuthorizedPrincipalsFile.  The pro-
    ///      gram must be owned by root, not writable by group or others and
    ///      specified by an absolute path.  Arguments to
    ///      AuthorizedPrincipalsCommand accept the tokens described in the
    ///      TOKENS section.  If no arguments are specified then the username
    ///      of the target user is used.

    ///      The program should produce on standard output zero or more lines
    ///      of AuthorizedPrincipalsFile output.  If either
    ///      AuthorizedPrincipalsCommand or AuthorizedPrincipalsFile is speci-
    ///      fied, then certificates offered by the client for authentication
    ///      must contain a principal that is listed.  By default, no
    ///      AuthorizedPrincipalsCommand is run.
    AuthorizedPrincipalsCommand,

    ///      Specifies the user under whose account the
    ///      AuthorizedPrincipalsCommand is run.  It is recommended to use a
    ///      dedicated user that has no other role on the host than running
    ///      authorized principals commands.  If AuthorizedPrincipalsCommand
    ///      is specified but AuthorizedPrincipalsCommandUser is not, then
    ///      sshd(8) will refuse to start.
    AuthorizedPrincipalsCommandUser,

    ///      Specifies a file that lists principal names that are accepted for
    ///      certificate authentication.  When using certificates signed by a
    ///      key listed in TrustedUserCAKeys, this file lists names, one of
    ///      which must appear in the certificate for it to be accepted for
    ///      authentication.  Names are listed one per line preceded by key
    ///      options (as described in AUTHORIZED_KEYS FILE FORMAT in sshd(8)).
    ///      Empty lines and comments starting with `#' are ignored.

    ///      Arguments to AuthorizedPrincipalsFile accept the tokens described
    ///      in the TOKENS section.  After expansion, AuthorizedPrincipalsFile
    ///      is taken to be an absolute path or one relative to the user's
    ///      home directory.  The default is none, i.e. not to use a princi-
    ///      pals file - in this case, the username of the user must appear in
    ///      a certificate's principals list for it to be accepted.

    ///      Note that AuthorizedPrincipalsFile is only used when authentica-
    ///      tion proceeds using a CA listed in TrustedUserCAKeys and is not
    ///      consulted for certification authorities trusted via
    ///      ~/.ssh/authorized_keys, though the principals= key option offers
    ///      a similar facility (see sshd(8) for details).
    AuthorizedPrincipalsFile,

    /// The contents of the specified file are sent to the remote user
    ///      before authentication is allowed. If the argument is none then
    ///      no banner is displayed.  By default, no banner is displayed.
    Banner,

    ///      Specifies the pathname of a directory to chroot(2) to after au-
    ///      thentication.  At session startup sshd(8) checks that all compo-
    ///      nents of the pathname are root-owned directories which are not
    ///      writable by any other user or group.  After the chroot, sshd(8)
    ///      changes the working directory to the user's home directory.  Ar-
    ///      guments to ChrootDirectory accept the tokens described in the
    ///      TOKENS section.

    ///      The ChrootDirectory must contain the necessary files and directo-
    ///      ries to support the user's session.  For an interactive session
    ///      this requires at least a shell, typically sh(1), and basic /dev
    ///      nodes such as null(4), zero(4), stdin(4), stdout(4), stderr(4),
    ///      and tty(4) devices.  For file transfer sessions using SFTP no ad-
    ///      ditional configuration of the environment is necessary if the in-
    ///      process sftp-server is used, though sessions which use logging
    ///      may require /dev/log inside the chroot directory on some operat-
    ///      ing systems (see sftp-server(8) for details).

    ///      For safety, it is very important that the directory hierarchy be
    ///      prevented from modification by other processes on the system (es-
    ///      pecially those outside the jail). Misconfiguration can lead to
    ///      unsafe environments which sshd(8) cannot detect.

    ///      The default is none, indicating not to chroot(2).
    ChrootDirectory,

    ///      Sets the number of client alive messages which may be sent with-
    ///      out sshd(8) receiving any messages back from the client.  If this
    ///      threshold is reached while client alive messages are being sent,
    ///      sshd will disconnect the client, terminating the session. It is
    ///      important to note that the use of client alive messages is very
    ///      different from TCPKeepAlive.  The client alive messages are sent
    ///      through the encrypted channel and therefore will not be spoofa-
    ///      ble.  The TCP keepalive option enabled by TCPKeepAlive is spoofa-
    ///      ble.  The client alive mechanism is valuable when the client or
    ///      server depend on knowing when a connection has become inactive.

    ///      The default value is 3.  If ClientAliveInterval is set to 15, and
    ///      ClientAliveCountMax is left at the default, unresponsive SSH
    ///      clients will be disconnected after approximately 45 seconds.
    ClientAliveCountMax,

    ///      Sets a timeout interval in seconds after which if no data has
    ///      been received from the client, sshd(8) will send a message
    ///      through the encrypted channel to request a response from the
    ///      client.  The default is 0, indicating that these messages will
    ///      not be sent to the client.
    ClientAliveInterval,

    ///      This keyword can be followed by a list of group name patterns,
    ///      separated by spaces.  Login is disallowed for users whose primary
    ///      group or supplementary group list matches one of the patterns.
    ///      Only group names are valid; a numerical group ID is not recog-
    ///      nized.  By default, login is allowed for all groups.  The al-
    ///      low/deny directives are processed in the following order:
    ///      DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.

    ///      See PATTERNS in ssh_config(5) for more information on patterns.
    DenyGroups,

    ///      This keyword can be followed by a list of user name patterns,
    ///      separated by spaces.  Login is disallowed for user names that
    ///      match one of the patterns.  Only user names are valid; a numeri-
    ///      cal user ID is not recognized.  By default, login is allowed for
    ///      all users.  If the pattern takes the form USER@HOST then USER and
    ///      HOST are separately checked, restricting logins to particular
    ///      users from particular hosts.  HOST criteria may additionally con-
    ///      tain addresses to match in CIDR address/masklen format.  The al-
    ///      low/deny directives are processed in the following order:
    ///      DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.

    ///      See PATTERNS in ssh_config(5) for more information on patterns.
    DenyUsers,

    ///      Disables all forwarding features, including X11, ssh-agent(1),
    ///      TCP and StreamLocal.  This option overrides all other forwarding-
    ///      related options and may simplify restricted configurations.
    DisableForwarding,

    ///      Writes a temporary file containing a list of authentication meth-
    ///      ods and public credentials (e.g. keys) used to authenticate the
    ///      user.  The location of the file is exposed to the user session
    ///      through the SSH_USER_AUTH environment variable.  The default is
    ///      no.
    ExposeAuthInfo,

    ///      Forces the execution of the command specified by ForceCommand,
    ///      ignoring any command supplied by the client and ~/.ssh/rc if
    ///      present.  The command is invoked by using the user's login shell
    ///      with the -c option.  This applies to shell, command, or subsystem
    ///      execution.  It is most useful inside a Match block.  The command
    ///      originally supplied by the client is available in the
    ///      SSH_ORIGINAL_COMMAND environment variable.  Specifying a command
    ///      of internal-sftp will force the use of an in-process SFTP server
    ///      that requires no support files when used with ChrootDirectory.
    ///      The default is none.
    ForceCommand,

    ///      Specifies whether to automatically destroy the user's credentials
    ///      cache on logout.  The default is yes.
    GSSAPICleanupCredentials,

    ///      Determines whether to be strict about the identity of the GSSAPI
    ///      acceptor a client authenticates against.  If set to yes then the
    ///      client must authenticate against the host service on the current
    ///      hostname. If set to no then the client may authenticate against
    ///      any service key stored in the machine's default store.  This fa-
    ///      cility is provided to assist with operation on multi homed ma-
    ///      chines.  The default is yes.
    GSSAPIStrictAcceptorCheck,

    ///      Specifies the key types that will be accepted for hostbased au-
    ///      thentication as a list of comma-separated patterns.  Alternately
    ///      if the specified value begins with a `+' character, then the
    ///      specified key types will be appended to the default set instead
    ///      of replacing them.  If the specified value begins with a `-'
    ///      character, then the specified key types (including wildcards)
    ///      will be removed from the default set instead of replacing them.
    ///      The default for this option is:

    /// ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp384-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp521-cert-v01@openssh.com,
    /// ssh-ed25519-cert-v01@openssh.com,
    /// rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,
    /// ssh-rsa-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
    /// ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa

    ///      The list of available key types may also be obtained using "ssh
    ///      -Q key".
    HostbasedAcceptedKeyTypes,

    ///      Specifies whether or not the server will attempt to perform a re-
    ///      verse name lookup when matching the name in the ~/.shosts,
    ///      ~/.rhosts, and /etc/hosts.equiv files during
    ///      HostbasedAuthentication.  A setting of yes means that sshd(8)
    ///      uses the name supplied by the client rather than attempting to
    ///      resolve the name from the TCP connection itself.  The default is
    ///      no.
    HostbasedUsesNameFromPacketOnly,

    ///      Specifies a file containing a public host certificate.  The cer-
    ///      tificate's public key must match a private host key already spec-
    ///      ified by HostKey. The default behaviour of sshd(8) is not to
    ///      load any certificates.
    HostCertificate,

    ///      Specifies a file containing a private host key used by SSH.  The
    ///      defaults are /etc/ssh/ssh_host_ecdsa_key,
    ///      /etc/ssh/ssh_host_ed25519_key and /etc/ssh/ssh_host_rsa_key.

    ///      Note that sshd(8) will refuse to use a file if it is group/world-
    ///      accessible and that the HostKeyAlgorithms option restricts which
    ///      of the keys are actually used by sshd(8).

    ///      It is possible to have multiple host key files.  It is also pos-
    ///      sible to specify public host key files instead.  In this case op-
    ///      erations on the private key will be delegated to an ssh-agent(1).
    HostKey,

    ///      Identifies the UNIX-domain socket used to communicate with an
    ///      agent that has access to the private host keys.  If the string
    ///      "SSH_AUTH_SOCK" is specified, the location of the socket will be
    ///      read from the SSH_AUTH_SOCK environment variable.
    HostKeyAgent,

    ///      Specifies that .rhosts and .shosts files will not be used in
    ///      HostbasedAuthentication.

    ///      /etc/hosts.equiv and /etc/ssh/shosts.equiv are still used.  The
    ///      default is yes.
    IgnoreRhosts,

    ///      Specifies whether sshd(8) should ignore the user's
    ///      ~/.ssh/known_hosts during HostbasedAuthentication and use only
    ///      the system-wide known hosts file /etc/ssh/known_hosts.  The de-
    ///      fault is no.
    IgnoreUserKnownHosts,

    ///      Specifies whether the password provided by the user for
    ///      PasswordAuthentication will be validated through the Kerberos
    ///      KDC.  To use this option, the server needs a Kerberos servtab
    ///      which allows the verification of the KDC's identity.  The default
    ///      is no.
    KerberosAuthentication,

    ///      If AFS is active and the user has a Kerberos 5 TGT, attempt to
    ///      acquire an AFS token before accessing the user's home directory.
    ///      The default is no.
    KerberosGetAFSToken,

    ///      If password authentication through Kerberos fails then the pass-
    ///      word will be validated via any additional local mechanism such as
    ///      /etc/passwd.  The default is yes.
    KerberosOrLocalPasswd,

    ///      Specifies whether to automatically destroy the user's ticket
    ///      cache file on logout.  The default is yes.
    KerberosTicketCleanup,

    ///      Specifies the local addresses sshd(8) should listen on.  The fol-
    ///      lowing forms may be used:

    ///  ListenAddress hostname|address [rdomain domain]
    ///  ListenAddress hostname:port [rdomain domain]
    ///  ListenAddress IPv4_address:port [rdomain domain]
    ///  ListenAddress [hostname|address]:port [rdomain domain]

    ///      The optional rdomain qualifier requests sshd(8) listen in an ex-
    ///      plicit routing domain.  If port is not specified, sshd will lis-
    ///      ten on the address and all Port options specified.  The default
    ///      is to listen on all local addresses on the current default rout-
    ///      ing domain.  Multiple ListenAddress options are permitted.  For
    ///      more information on routing domains, see rdomain(4).
    ListenAddress,

    ///      The server disconnects after this time if the user has not suc-
    ///      cessfully logged in.  If the value is 0, there is no time limit.
    ///      The default is 120 seconds.
    LoginGraceTime,

    ///      Specifies the maximum number of authentication attempts permitted
    ///      per connection.  Once the number of failures reaches half this
    ///      value, additional failures are logged.  The default is 6.
    MaxAuthTries,

    ///      Specifies the maximum number of open shell, login or subsystem
    ///      (e.g. sftp) sessions permitted per network connection.  Multiple
    ///      sessions may be established by clients that support connection
    ///      multiplexing.  Setting MaxSessions to 1 will effectively disable
    ///      session multiplexing, whereas setting it to 0 will prevent all
    ///      shell, login and subsystem sessions while still permitting for-
    ///      warding.  The default is 10.
    MaxSessions,

    ///      Specifies the maximum number of concurrent unauthenticated con-
    ///      nections to the SSH daemon.  Additional connections will be
    ///      dropped until authentication succeeds or the LoginGraceTime ex-
    ///      pires for a connection.  The default is 10:30:100.

    ///      Alternatively, random early drop can be enabled by specifying the
    ///      three colon separated values start:rate:full (e.g. "10:30:60").
    ///      sshd(8) will refuse connection attempts with a probability of
    ///      rate/100 (30%) if there are currently start (10) unauthenticated
    ///      connections.  The probability increases linearly and all connec-
    ///      tion attempts are refused if the number of unauthenticated con-
    ///      nections reaches full (60).
    MaxStartups,

    ///      When password authentication is allowed, it specifies whether the
    ///      server allows login to accounts with empty password strings.  The
    ///      default is no.
    PermitEmptyPasswords,

    ///      Specifies the addresses/ports on which a remote TCP port forward-
    ///      ing may listen.  The listen specification must be one of the fol-
    ///      lowing forms:

    ///    PermitListen port
    ///    PermitListen host:port

    ///      Multiple permissions may be specified by separating them with
    ///      whitespace.  An argument of any can be used to remove all re-
    ///      strictions and permit any listen requests.  An argument of none
    ///      can be used to prohibit all listen requests.  The host name may
    ///      contain wildcards as described in the PATTERNS section in
    ///      ssh_config(5).  The wildcard `*' can also be used in place of a
    ///      port number to allow all ports.  By default all port forwarding
    ///      listen requests are permitted.  Note that the GatewayPorts option
    ///      may further restrict which addresses may be listened on.  Note
    ///      also that ssh(1) will request a listen host of "localhost" if no
    ///      listen host was specifically requested, and this this name is
    ///      treated differently to explicit localhost addresses of
    ///      "127.0.0.1" and "::1".
    PermitListen,

    ///      Specifies the destinations to which TCP port forwarding is per-
    ///      mitted.  The forwarding specification must be one of the follow-
    ///      ing forms:

    ///   PermitOpen host:port
    ///   PermitOpen IPv4_addr:port
    ///   PermitOpen [IPv6_addr]:port

    ///      Multiple forwards may be specified by separating them with white-
    ///      space.  An argument of any can be used to remove all restrictions
    ///      and permit any forwarding requests.  An argument of none can be
    ///      used to prohibit all forwarding requests. The wildcard `*' can
    ///      be used for host or port to allow all hosts or ports, respec-
    ///      tively.  By default all port forwarding requests are permitted.
    PermitOpen,

    ///      Specifies whether root can log in using ssh(1).  The argument
    ///      must be yes, prohibit-password, forced-commands-only, or no.  The
    ///      default is no.  Note that if ChallengeResponseAuthentication and
    ///      UsePAM are both yes, this setting may be overridden by the PAM
    ///      policy.

    ///      If this option is set to prohibit-password (or its deprecated
    ///      alias, without-password), password and keyboard-interactive au-
    ///      thentication are disabled for root.

    ///      If this option is set to forced-commands-only, root login with
    ///      public key authentication will be allowed, but only if the
    ///      command option has been specified (which may be useful for taking
    ///      remote backups even if root login is normally not allowed).  All
    ///      other authentication methods are disabled for root.

    ///      If this option is set to no, root is not allowed to log in.
    PermitRootLogin,

    ///      Specifies whether pty(4) allocation is permitted. The default is
    ///      yes.
    PermitTTY,

    ///      Specifies whether tun(4) device forwarding is allowed.  The argu-
    ///      ment must be yes, point-to-point (layer 3), ethernet (layer 2),
    ///      or no.  Specifying yes permits both point-to-point and ethernet.
    ///      The default is no.

    ///      Independent of this setting, the permissions of the selected
    ///      tun(4) device must allow access to the user.
    PermitTunnel,

    ///      Specifies whether ~/.ssh/environment and environment= options in
    ///      ~/.ssh/authorized_keys are processed by sshd(8).  Valid options
    ///      are yes, no or a pattern-list specifying which environment vari-
    ///      able names to accept (for example "LANG,LC_*").  The default is
    ///      no.  Enabling environment processing may enable users to bypass
    ///      access restrictions in some configurations using mechanisms such
    ///      as LD_PRELOAD.
    PermitUserEnvironment,

    ///      Specifies whether any ~/.ssh/rc file is executed. The default is
    ///      yes.
    PermitUserRC,

    ///      Specifies the file that contains the process ID of the SSH dae-
    ///      mon, or none to not write one.  The default is /var/run/sshd.pid.
    PidFile,

    ///      Specifies whether sshd(8) should print the date and time of the
    ///      last user login when a user logs in interactively.  The default
    ///      is yes.
    PrintLastLog,

    ///      Specifies whether sshd(8) should print /etc/motd when a user logs
    ///      in interactively. (On some systems it is also printed by the
    ///      shell, /etc/profile, or equivalent.)  The default is yes.
    PrintMotd,

    ///      Specifies revoked public keys file, or none to not use one.  Keys
    ///      listed in this file will be refused for public key authentica-
    ///      tion.  Note that if this file is not readable, then public key
    ///      authentication will be refused for all users.  Keys may be speci-
    ///      fied as a text file, listing one public key per line, or as an
    ///      OpenSSH Key Revocation List (KRL) as generated by ssh-keygen(1).
    ///      For more information on KRLs, see the KEY REVOCATION LISTS sec-
    ///      tion in ssh-keygen(1).
    RevokedKeys,

    ///      Specifies an explicit routing domain that is applied after au-
    ///      thentication has completed.  The user session, as well and any
    ///      forwarded or listening IP sockets, will be bound to this
    ///      rdomain(4).  If the routing domain is set to %D, then the domain
    ///      in which the incoming connection was received will be applied.
    RDomain,

    ///      Specifies whether sshd(8) should check file modes and ownership
    ///      of the user's files and home directory before accepting login.
    ///      This is normally desirable because novices sometimes accidentally
    ///      leave their directory or files world-writable.  The default is
    ///      yes.  Note that this does not apply to ChrootDirectory, whose
    ///      permissions and ownership are checked unconditionally.
    StrictModes,

    ///      Configures an external subsystem (e.g. file transfer daemon).
    ///      Arguments should be a subsystem name and a command (with optional
    ///      arguments) to execute upon subsystem request.

    ///      The command sftp-server implements the SFTP file transfer subsys-
    ///      tem.

    ///      Alternately the name internal-sftp implements an in-process SFTP
    ///      server.  This may simplify configurations using ChrootDirectory
    ///      to force a different filesystem root on clients.

    ///      By default no subsystems are defined.
    Subsystem,

    ///      Specifies a file containing public keys of certificate authori-
    ///      ties that are trusted to sign user certificates for authentica-
    ///      tion, or none to not use one.  Keys are listed one per line;
    ///      empty lines and comments starting with `#' are allowed.  If a
    ///      certificate is presented for authentication and has its signing
    ///      CA key listed in this file, then it may be used for authentica-
    ///      tion for any user listed in the certificate's principals list.
    ///      Note that certificates that lack a list of principals will not be
    ///      permitted for authentication using TrustedUserCAKeys.  For more
    ///      details on certificates, see the CERTIFICATES section in
    ///      ssh-keygen(1).
    TrustedUserCAKeys,

    ///      Specifies whether sshd(8) attempts to send authentication success
    ///      and failure messages to the blacklistd(8) daemon. The default is
    ///      no.  For forward compatibility with an upcoming blacklistd re-
    ///      name, the UseBlocklist alias can be used instead.
    UseBlacklist,

    ///  Specifies whether sshd(8) should look up the remote host name,
    ///      and to check that the resolved host name for the remote IP ad-
    ///      dress maps back to the very same IP address.

    ///      If this option is set to no, then only addresses and not host
    ///      names may be used in ~/.ssh/authorized_keys from and sshd_config
    ///      Match Host directives.  The default is "yes".
    UseDNS,

    /// Enables the Pluggable Authentication Module interface.  If set to
    ///      yes this will enable PAM authentication using
    ///      ChallengeResponseAuthentication and PasswordAuthentication in ad-
    ///      dition to PAM account and session module processing for all au-
    ///      thentication types.

    ///      Because PAM challenge-response authentication usually serves an
    ///      equivalent role to password authentication, you should disable
    ///      either PasswordAuthentication or ChallengeResponseAuthentication.

    ///      If UsePAM is enabled, you will not be able to run sshd(8) as a
    ///      non-root user.  The default is yes.
    UsePAM,

    ///      Optionally specifies additional text to append to the SSH proto-
    ///      col banner sent by the server upon connection.  The default is
    ///      "FreeBSD-20200214".  The value none may be used to disable this.
    VersionAddendum,

    ///      Specifies the first display number available for sshd(8)'s X11
    ///      forwarding.  This prevents sshd from interfering with real X11
    ///      servers.  The default is 10.
    X11DisplayOffset,

    ///      Specifies whether X11 forwarding is permitted.  The argument must
    ///      be yes or no.  The default is yes.

    ///      When X11 forwarding is enabled, there may be additional exposure
    ///      to the server and to client displays if the sshd(8) proxy display
    ///      is configured to listen on the wildcard address (see
    ///      X11UseLocalhost), though this is not the default. Additionally,
    ///      the authentication spoofing and authentication data verification
    ///      and substitution occur on the client side.  The security risk of
    ///      using X11 forwarding is that the client's X11 display server may
    ///      be exposed to attack when the SSH client requests forwarding (see
    ///      the warnings for ForwardX11 in ssh_config(5)).  A system adminis-
    ///      trator may have a stance in which they want to protect clients
    ///      that may expose themselves to attack by unwittingly requesting
    ///      X11 forwarding, which can warrant a no setting.

    ///      Note that disabling X11 forwarding does not prevent users from
    ///      forwarding X11 traffic, as users can always install their own
    ///      forwarders.
    X11Forwarding,

    ///      Specifies whether sshd(8) should bind the X11 forwarding server
    ///      to the loopback address or to the wildcard address.  By default,
    ///      sshd binds the forwarding server to the loopback address and sets
    ///      the hostname part of the DISPLAY environment variable to
    ///      localhost.  This prevents remote hosts from connecting to the
    ///      proxy display.  However, some older X11 clients may not function
    ///      with this configuration.  X11UseLocalhost may be set to no to
    ///      specify that the forwarding server should be bound to the wild-
    ///      card address.  The argument must be yes or no.  The default is
    ///      yes.
    X11UseLocalhost,

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

    /// Specifies whether keys should be automatically added to a running
    /// ssh-agent(1).
    ///
    /// If this option is set to yes and a key is loaded from a
    /// file, the key and its passphrase are added to the agent with the default
    /// lifetime, as if by ssh-add(1). If this option is set to ask, ssh(1)
    /// will require confirmation using the SSH_ASKPASS program before adding a
    /// key (see ssh-add(1) for details). If this option is set to confirm,
    /// each use of the key must be confirmed, as if the -c option was specified
    /// to ssh-add(1). If this option is set to no, no keys are added to the
    /// agent. Alternately, this option may be specified as a time interval
    /// using the format described in the TIME FORMATS section of sshd_config(5)
    /// to specify the key's lifetime in ssh-agent(1), after which it will
    /// automatically be removed. The argument must be no (the default), yes,
    /// confirm (optionally followed by a time interval), ask or a time
    /// interval.
    AddKeysToAgent,

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

    /// Use the address of the specified interface on the local machine as the
    /// source address of the connection.
    BindInterface,

    /// When CanonicalizeHostname is enabled, this option specifies the list of
    /// domain suffixes in which to search for the specified destination host.
    CanonicalDomains,

    /// Specifies whether to fail with an error when hostname canonicalization
    /// fails. The default, yes, will attempt to look up the unqualified
    /// hostname using the system resolver's search rules. A value of no will
    /// cause ssh(1) to fail instantly if CanonicalizeHostname is enabled and
    /// the target hostname cannot be found in any of the domains specified by
    /// CanonicalDomains.
    CanonicalizeFallbackLocal,

    /// Controls whether explicit hostname canonicalization is performed.
    ///
    /// The default, `no`, is not to perform any name rewriting and let the
    /// system resolver handle all hostname lookups. If set to `yes` then,
    /// for connections that do not use a `ProxyCommand` or ProxyJump, ssh(1)
    /// will attempt to canonicalize the hostname specified on the command
    /// line using the CanonicalDomains suffixes and
    /// `CanonicalizePermittedCNAMEs` rules. If `CanonicalizeHostname` is set
    /// to `always`, then canonicalization is applied to proxied connections
    /// too.
    ///
    /// If this option is enabled, then the configuration files are processed
    /// again using the new target name to pick up any new configuration in
    /// matching Host and Match stanzas. A value of none disables the use of a
    /// ProxyJump host.
    CanonicalizeHostname,

    /// Specifies the maximum number of dot characters in a hostname before
    /// canonicalization is disabled. The default, 1, allows a single dot (i.e.
    /// hostname.subdomain).
    CanonicalizeMaxDots,

    /// Specifies rules to determine whether CNAMEs should be followed when
    /// canonicalizing hostnames.
    ///
    /// The rules consist of one or more arguments of
    /// `source_domain_list:target_domain_list`, where source_domain_list is a
    /// pattern-list of domains that may follow CNAMEs in canonicalization, and
    /// target_domain_list is a pattern-list of domains that they may resolve
    /// to.
    ///
    /// For example, `"*.a.example.com:*.b.example.com,*.c.example.com"` will
    /// allow hostnames matching `"*.a.example.com"` to be canonicalized to
    /// names in the `"*.b.example.com"` or `"*.c.example.com"` domains.
    CanonicalizePermittedCNAMEs,

    /// Specifies which algorithms are allowed for signing of
    /// certificates by certificate authorities (CAs).
    ///
    /// The default
    /// is:
    ///
    /// ```text
    /// ssh-ed25519,
    /// ecdsa-sha2-nistp256,
    /// ecdsa-sha2-nistp384,
    /// ecdsa-sha2-nistp521,
    /// sk-ssh-ed25519@openssh.com,
    /// sk-ecdsa-sha2-nistp256@openssh.com,
    /// rsa-sha2-512,
    /// rsa-sha2-256
    /// ```
    ///
    /// If the specified list begins with a `+` character, then the specified
    /// algorithms will be appended to the default set instead of replacing
    /// them. If the specified list begins with a `-` character, then the
    /// specified algorithms (including wildcards) will be removed from the
    /// default set instead of replacing them.
    ///
    /// ssh(1) will not accept host certificates signed using algorithms other
    /// than those specified.
    CASignatureAlgorithms,

    /// Specifies a file from which the user's certificate is read.
    ///
    /// A corresponding private key must be provided separately in order to use
    /// this certificate either from an IdentityFile directive or -i flag to
    /// ssh(1), via ssh-agent(1), or via a `PKCS11Provider` or
    /// `SecurityKeyProvider`.
    ///
    /// Arguments to CertificateFile may use the tilde syntax to refer to a
    /// user's home directory, the tokens described in the TOKENS section and
    /// environment variables as described in the ENVIRONMENT VARIABLES section.
    ///
    /// It is possible to have multiple certificate files specified in
    /// configuration files; these certificates will be tried in sequence.
    /// Multiple CertificateFile directives will add to the list of certificates
    /// used for authentication.
    CertificateFile,

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

    /// When used in conjunction with ControlMaster, specifies that the master
    /// connection should remain open in the background (waiting for future
    /// client connections) after the initial client connection has been
    /// closed. If set to no (the default), then the master connection will
    /// not be placed into the background, and will close as soon as the
    /// initial client connection  is closed. If set to yes or 0, then the
    /// master connection will remain in the background indefinitely (until
    /// killed or closed via a mechanism such as the "ssh -O exit"). If set
    /// to a time in seconds, or a time in any of the formats documented in
    /// sshd_config(5), then the backgrounded master connection will
    /// automatically terminate after it has remained idle (with no client
    /// connections) for the specified time.
    ControlPersist,

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

    /// Specifies the hash algorithm used when displaying key fingerprints.
    /// Valid options are: md5 and sha256 (the default).
    FingerprintHash,

    /// Requests ssh to go to background just before command execution. This is
    /// useful if ssh is going to ask for passwords or passphrases, but the user
    /// wants it in the background. This implies the StdinNull configuration
    /// option being set to `yes`. The recommended way to start X11 programs at
    /// a remote site is with something like ssh -f host xterm, which is the
    /// same as ssh host xterm if the ForkAfterAuthentication configuration
    /// option is set to `yes`.
    ///
    /// If the ExitOnForwardFailure configuration option is set to `yes`, then a
    /// client started with the ForkAfterAuthentication configuration option
    /// being set to `yes` will wait for all remote port forwards to be
    /// successfully established before placing itself in the background. The
    /// argument to this keyword must be yes (same as the -f option) or no (the
    /// default).
    ForkAfterAuthentication,

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

    /// Specify a timeout for untrusted X11 forwarding using the format
    /// described in the TIME FORMATS section of sshd_config(5). X11 connections
    /// received by ssh(1) after this time will be refused. Setting
    /// ForwardX11Timeout to zero will disable the timeout and permit X11
    /// forwarding for the life of the connection. The default is to disable
    /// untrusted X11 forwarding after twenty minutes has elapsed.
    ForwardX11Timeout,

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

    /// Specifies whether key exchange based on GSSAPI may be used.
    ///
    /// When using GSSAPI key exchange the server need not have a host key. The
    /// default is `no`. Note that this option applies to protocol version 2
    /// only.
    GSSAPIKeyExchange,

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

    /// Specifies the signature algorithms that will be used for hostbased
    /// authentication as a comma-separated list of patterns. Alternately if the
    /// specified list begins with a `+` character, then the specified signature
    /// algorithms will be appended to the default set instead of replacing
    /// them. If the specified list begins with a `-` character, then the
    /// specified signature algorithms (including wildcards) will be removed
    /// from the default set instead of replacing them. If the specified list
    /// begins with a `^` character, then the specified signature algorithms
    /// will be placed at the head of the default set. The default for this
    /// option is:
    ///
    /// ```text
    /// ssh-ed25519-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp384-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp521-cert-v01@openssh.com,
    /// sk-ssh-ed25519-cert-v01@openssh.com,
    /// sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// rsa-sha2-512-cert-v01@openssh.com,
    /// rsa-sha2-256-cert-v01@openssh.com,
    /// ssh-rsa-cert-v01@openssh.com,
    /// ssh-ed25519,
    /// ecdsa-sha2-nistp256,
    /// ecdsa-sha2-nistp384,
    /// ecdsa-sha2-nistp521,
    /// sk-ssh-ed25519@openssh.com,
    /// sk-ecdsa-sha2-nistp256@openssh.com,
    /// rsa-sha2-512,
    /// rsa-sha2-256,ssh-rsa
    /// ```
    ///
    /// The -Q option of ssh(1) may be used to list supported signature
    /// algorithms. This was formerly named `HostbasedKeyTypes`.
    HostbasedAcceptedAlgorithms,

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

    /// Specifies the real host name to log into. This can be used to specify
    /// nicknames or abbreviations for hosts. Arguments to Hostname accept the
    /// tokens described in the TOKENS section. Numeric IP addresses are also
    /// permitted (both on the command line and in Hostname specifications). The
    /// default is the name given on the command line.
    Hostname,

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

    /// Specifies the UNIX-domain socket used to communicate with the
    /// authentication agent.
    ///
    /// This option overrides the `SSH_AUTH_SOCK` environment variable and can
    /// be used to select a specific agent. Setting the socket name to none
    /// disables the use of an authentication agent. If the string
    /// `"SSH_AUTH_SOCK"` is specified, the location of the socket will be read
    /// from the `SSH_AUTH_SOCK` environment variable. Otherwise if the
    /// specified value begins with a `$` character, then it will be treated
    /// as an environment variable containing the location of the socket.
    ///
    /// Arguments to IdentityAgent may use the tilde syntax to refer to a user's
    /// home directory, the tokens described in the TOKENS section and
    /// environment variables as described in the ENVIRONMENT VARIABLES section.
    IdentityAgent,

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

    /// Specifies a pattern-list of unknown options to be ignored if they are
    /// encountered in configuration parsing. This may be used to suppress
    /// errors if ssh_config contains options that are unrecognised by ssh(1).
    /// It is recommended that IgnoreUnknown be listed early in the
    /// configuration file as it will not be applied to unknown options that
    /// appear before it.
    IgnoreUnknown,

    /// Include the specified configuration file(s). Multiple pathnames may be
    /// specified and each pathname may contain glob(7) wildcards and, for user
    /// configurations, shell-like `~` references to user home directories.
    /// Wildcards will be expanded and processed in lexical order. Files without
    /// absolute paths are assumed to be in `~/.ssh` if included in a user
    /// configuration file or `/etc/ssh` if included from the system
    /// configuration file. Include directive may appear inside a Match or
    /// Host block to perform conditional inclusion.
    Include,

    /// Specifies the IPv4 type-of-service or DSCP class for connections.
    ///
    /// Accepted values are `af11`, `af12`, `af13`, `af21`, `af22`, `af23`,
    /// `af31`, `af32`, `af33`, `af41`, `af42`, `af43`, `cs0`, `cs1`, `cs2`,
    /// `cs3`, `cs4`, `cs5`, `cs6`, `cs7`, `ef`, `le`, `lowdelay`, `throughput`,
    /// `reliability`, a numeric value, or `none` to use the operating system
    /// default. This option may take one or two arguments, separated by
    /// whitespace. If one argument is specified, it is used as the packet class
    /// unconditionally. If two values are specified, the first is automatically
    /// selected for interactive sessions and the second for non-interactive
    /// sessions. The default is `af21` (Low-Latency Data) for interactive
    /// sessions and `cs1` (Lower Effort) for non-interactive sessions.
    IPQoS,

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

    /// Specifies the key types that will be accepted for public key au-
    /// thentication as a list of comma-separated patterns.  Alternately
    /// if the specified value begins with a `+' character, then the
    /// specified key types will be appended to the default set instead
    /// of replacing them. If the specified value begins with a `-'
    /// character, then the specified key types (including wildcards)
    /// will be removed from the default set instead of replacing them.
    /// The default for this option is:
    ///
    /// ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp384-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp521-cert-v01@openssh.com,
    /// ssh-ed25519-cert-v01@openssh.com,
    /// rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,
    /// ssh-rsa-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,
    /// ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa
    ///
    ///  The list of available key types may also be obtained using "ssh
    ///  -Q key".
    PubkeyAcceptedKeyTypes,

    /// Specifies the available KEX (Key Exchange) algorithms.
    ///
    /// Multiple algorithms must be comma-separated. If the specified list
    /// begins with a `+` character, then the specified methods will be appended
    /// to the default set instead of replacing them. If the specified list
    /// begins with a `-` character, then the specified methods (including
    /// wildcards) will be removed from the default set instead of replacing
    /// them. If the specified list begins with a `^` character, then the
    /// specified methods will be placed at the head of the default set. The
    /// default is:
    ///
    /// ```text
    /// curve25519-sha256,
    /// curve25519-sha256@libssh.org,
    /// ecdh-sha2-nistp256,
    /// ecdh-sha2-nistp384,
    /// ecdh-sha2-nistp521,
    /// diffie-hellman-group-exchange-sha256,
    /// diffie-hellman-group16-sha512,
    /// diffie-hellman-group18-sha512,
    /// diffie-hellman-group14-sha256
    /// ```
    ///
    /// The list of available key exchange algorithms may also be obtained using
    /// `ssh -Q kex`.
    KexAlgorithms,

    /// Specifies a command to use to obtain a list of host keys, in addition to
    /// those listed in `UserKnownHostsFile` and `GlobalKnownHostsFile`.
    ///
    /// This command is executed after the files have been read. It may write
    /// host key lines to standard output in identical format to the usual
    /// files (described in the VERIFYING HOST KEYS section in ssh(1)).
    /// Arguments to KnownHostsCommand accept the tokens described in the
    /// TOKENS section. The command may be invoked multiple times per
    /// connection: once when preparing the preference list of host key
    /// algorithms to use, again to obtain the host key for the requested
    /// host name and, if CheckHostIP is enabled, one more time to obtain
    /// the host key matching the server's address. If the command exits
    /// abnormally or returns a non-zero exit status then the connection is
    /// terminated.
    KnownHostsCommand,

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

    /// Specify one or more overrides to LogLevel.
    ///
    /// An override consists of a pattern lists that matches the source file,
    /// function and line number to force detailed logging for. For example, an
    /// override pattern of:
    ///
    /// ```text
    /// kex.c:*:1000,*:kex_exchange_identification():*,packet.c:*
    /// ```
    ///
    /// would enable detailed logging for line 1000 of kex.c, everything in the
    /// kex_exchange_identification() function, and all code in the packet.c
    /// file. This option is intended for debugging and no overrides are enabled
    /// by default.
    LogVerbose,

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

    /// Restricts the following declarations (up to the next Host or Match
    /// keyword) to be used only when the conditions following the Match keyword
    /// are satisfied. Match conditions are specified using one or more
    /// criteria or the single token all which always matches. The available
    /// criteria keywords are: canonical, final, exec, host, originalhost, user,
    /// and localuser. The all criteria must appear alone or immediately after
    /// canonical or final. Other criteria may be combined arbitrarily. All
    /// criteria but all, canonical, and final require an argument. Criteria may
    /// be negated by prepending an exclamation mark (`!`).
    ///
    /// The canonical keyword matches only when the configuration file is being
    /// re-parsed after hostname canonicalization (see the CanonicalizeHostname
    /// option). This may be useful to specify conditions that work with
    /// canonical host names only.
    ///
    /// The final keyword requests that the configuration be re-parsed
    /// (regardless of whether CanonicalizeHostname is enabled), and matches
    /// only during this final pass. If CanonicalizeHostname is enabled, then
    /// canonical and final match during the same pass.
    ///
    /// The exec keyword executes the specified command under the user's shell.
    /// If the command returns a zero exit status then the condition is
    /// considered true. Commands containing whitespace characters must be
    /// quoted. Arguments to exec accept the tokens described in the TOKENS
    /// section.
    ///
    /// The other keywords' criteria must be single entries or comma-separated
    /// lists and may use the wildcard and negation operators described in the
    /// PATTERNS section. The criteria for the host keyword are matched against
    /// the target hostname, after any substitution by the Hostname or
    /// CanonicalizeHostname options. The originalhost keyword matches against
    /// the hostname as it was specified on the command-line. The user keyword
    /// matches against the target username on the remote host. The localuser
    /// keyword matches against the name of the local user running ssh(1) (this
    /// keyword may be useful in system-wide ssh_config files).
    Match,

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

    /// Specifies the destinations to which remote TCP port forwarding is
    /// permitted when `RemoteForward` is used as a SOCKS proxy.
    ///
    /// The forwarding specification must be one of the following forms:
    ///
    /// ```text
    /// PermitRemoteOpen host:port
    /// PermitRemoteOpen IPv4_addr:port
    /// PermitRemoteOpen [IPv6_addr]:port
    /// ```
    ///
    /// Multiple forwards may be specified by separating them with whitespace.
    /// An argument of any can be used to remove all restrictions and permit any
    /// forwarding requests. An argument of none can be used to prohibit all
    /// forwarding requests. The wildcard `*` can be used for host or port to
    /// allow all hosts or ports respectively. Otherwise, no pattern matching or
    /// address lookups are performed on supplied names.
    PermitRemoteOpen,

    /// Specifies which PKCS#11 provider to use or none to indicate that no
    /// provider should be used (the default).
    ///
    /// The argument to this keyword is a path to the PKCS#11 shared library
    /// ssh(1) should use to communicate with a PKCS#11 token providing keys for
    /// user authentication.
    PKCS11Provider,

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

    /// Specifies one or more jump proxies as either `[user@]host[:port]` or an
    /// ssh URI.
    ///
    /// Multiple proxies may be separated by comma characters and will be
    /// visited sequentially. Setting this option will cause ssh(1) to connect
    /// to the target host by first making a ssh(1) connection to the specified
    /// ProxyJump host and then establishing a TCP forwarding to the ultimate
    /// target from there. Setting the host to none disables this option
    /// entirely.
    ///
    /// Note that this option will compete with the `ProxyCommand` option -
    /// whichever is specified first will prevent later instances of the other
    /// from taking effect.
    ///
    /// Note also that the configuration for the destination host (either
    /// supplied via the command-line or the configuration file) is not
    /// generally applied to jump hosts. `~/.ssh/config` should be used if
    /// specific configuration is required for jump hosts.
    ProxyJump,

    /// Specifies that `ProxyCommand` will pass a connected file descriptor back
    /// to ssh(1) instead of continuing to execute and pass data.
    ///
    /// The default is no.
    ProxyUseFdpass,

    /// Specifies the signature algorithms that will be used for public key
    /// authentication as a comma-separated list of patterns.
    ///
    /// If the specified list begins with a `+` character, then the algorithms
    /// after it will be appended to the default instead of replacing it. If the
    /// specified list begins with a `-` character, then the specified
    /// algorithms (including wildcards) will be removed from the default set
    /// instead of replacing them. If the specified list begins with a `^`
    /// character, then the specified algorithms will be placed at the head of
    /// the default set.
    ///
    /// The default for this option is:
    ///
    /// ```text
    /// ssh-ed25519-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp384-cert-v01@openssh.com,
    /// ecdsa-sha2-nistp521-cert-v01@openssh.com,
    /// sk-ssh-ed25519-cert-v01@openssh.com,
    /// sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,
    /// rsa-sha2-512-cert-v01@openssh.com,
    /// rsa-sha2-256-cert-v01@openssh.com,
    /// ssh-rsa-cert-v01@openssh.com,
    /// ssh-ed25519,
    /// ecdsa-sha2-nistp256,
    /// ecdsa-sha2-nistp384,
    /// ecdsa-sha2-nistp521,
    /// sk-ssh-ed25519@openssh.com,
    /// sk-ecdsa-sha2-nistp256@openssh.com,
    /// rsa-sha2-512,
    /// rsa-sha2-256,ssh-rsa
    /// ```
    ///
    /// The list of available signature algorithms may also be obtained using
    /// `ssh -Q PubkeyAcceptedAlgorithms`.
    PubkeyAcceptedAlgorithms,

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

    /// Specifies a command to execute on the remote machine after successfully
    ///  connecting to the server. The command string extends to the end of the
    ///  line, and is executed with the user's shell. Arguments to RemoteCommand
    ///  accept the tokens described in the TOKENS section.
    RemoteCommand,

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

    /// Specifies whether to request a pseudo-tty for the session. The
    /// argument may be one of: no (never request a TTY), yes (always
    ///  request a TTY when standard input is a TTY), force (always
    /// request a TTY) or auto (request a TTY when opening a login
    ///  session). This option mirrors the -t and -T flags for ssh(1).
    RequestTTY,

    /// Specifies revoked host public keys.
    ///
    /// Keys listed in this file will be refused for host authentication. Note
    /// that if this file does not exist or is not readable, then host
    /// authentication will be refused for all hosts. Keys may be specified as a
    /// text file, listing one public key per line, or as an OpenSSH Key
    /// Revocation List (KRL) as generated by ssh-keygen(1). For more
    /// information on KRLs, see the KEY REVOCATION LISTS section in
    /// ssh-keygen(1).
    RevokedHostKeys,

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

    /// Specifies a path to a library that will be used when loading any FIDO
    /// authenticator-hosted keys, overriding the default of using the built-in
    /// USB HID support.
    ///
    /// If the specified value begins with a `$` character, then it will be
    /// treated as an environment variable containing the path to the library.
    SecurityKeyProvider,

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

    /// May be used to either request invocation of a subsystem on the remote
    /// system, or to prevent the execution of a remote command at all.
    ///
    /// The latter is useful for just forwarding ports. The argument to this
    /// keyword must be none (same as the -N option), subsystem (same as the -s
    /// option) or default (shell or command execution).
    SessionType,

    /// Directly specify one or more environment variables and their contents to
    /// be sent to the server.
    ///
    /// Similarly to `SendEnv`, with the exception of the TERM variable, the
    /// server must be prepared to accept the environment variable.
    SetEnv,

    /// Specifies which smartcard device to use.
    ///
    /// The argument to this keyword is the device ssh(1) should use to
    /// communicate with a smartcard used for storing the user's private RSA
    /// key. By default, no device is specified and smartcard support is not
    /// activated.
    SmartcardDevice,

    /// Redirects stdin from `/dev/null` (actually, prevents reading from
    /// stdin).
    ///
    /// Either this or the equivalent -n option must be used when ssh is run in
    /// the background. The argument to this keyword must be yes (same as the -n
    /// option) or no (the default).
    StdinNull,

    /// Sets the octal file creation mode mask (umask) used when creating a
    /// Unix-domain socket file for local or remote port forwarding.
    ///
    /// This option is only used for port forwarding to a Unix-domain socket
    /// file.
    ///
    /// The default value is 0177, which creates a Unix-domain socket file that
    /// is readable and writable only by the owner. Note that not all operating
    /// systems honor the file mode on Unix-domain socket files.
    StreamLocalBindMask,

    /// Specifies whether to remove an existing Unix-domain socket file for
    /// local or remote port forwarding before creating a new one.
    ///
    /// If the socket file already exists and StreamLocalBindUnlink is not
    /// enabled, ssh will be unable to forward the port to the Unix-domain
    /// socket file. This option is only used for port forwarding to a
    /// Unix-domain socket file.
    ///
    /// The argument must be yes or no (the default).
    StreamLocalBindUnlink,

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

    /// Gives the facility code that is used when logging messages from ssh(1).
    ///
    /// The possible values are: `DAEMON`, `USER`, `AUTH`, `LOCAL0`, `LOCAL1`,
    /// `LOCAL2`, `LOCAL3`, `LOCAL4`, `LOCAL5`, `LOCAL6`, `LOCAL7`. The
    /// default is `USER`.
    SyslogFacility,

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

    /// Specifies whether ssh(1) should accept notifications of additional
    /// hostkeys from the server sent after authentication has completed and add
    /// them to `UserKnownHostsFile`.
    ///
    /// The argument must be `yes`, `no` or `ask`. This option allows learning
    /// alternate hostkeys for a server and supports graceful key rotation by
    /// allowing a server to send replacement public keys before old ones are
    /// removed.
    ///
    /// Additional hostkeys are only accepted if the key used to authenticate
    /// the host was already trusted or explicitly accepted by the user, the
    /// host was authenticated via `UserKnownHostsFile` (i.e. not
    /// `GlobalKnownHostsFile`) and the host was authenticated using a plain key
    /// and not a certificate.
    ///
    /// `UpdateHostKeys` is enabled by default if the user has not overridden
    /// the default `UserKnownHostsFile` setting and has not enabled
    /// VerifyHostKeyDNS, otherwise `UpdateHostKeys` will be set to no.
    ///
    /// If `UpdateHostKeys` is set to `ask`, then the user is asked to confirm
    /// the modifications to the known_hosts file. Confirmation is currently
    /// incompatible with ControlPersist, and will be disabled if it is enabled.
    ///
    /// Presently, only sshd(8) from OpenSSH 6.8 and greater support the
    /// "hostkeys@openssh.com" protocol extension used to inform the client of
    /// all the server's hostkeys.
    UpdateHostKeys,

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
        } else if s.eq_ignore_ascii_case("addkeystoagent") {
            Ok(Self::AddKeysToAgent)
        } else if s.eq_ignore_ascii_case("addressfamily") {
            Ok(Self::AddressFamily)
        } else if s.eq_ignore_ascii_case("batchmode") {
            Ok(Self::BatchMode)
        } else if s.eq_ignore_ascii_case("bindaddress") {
            Ok(Self::BindAddress)
        } else if s.eq_ignore_ascii_case("bindinterface") {
            Ok(Self::BindInterface)
        } else if s.eq_ignore_ascii_case("canonicaldomains") {
            Ok(Self::CanonicalDomains)
        } else if s.eq_ignore_ascii_case("canonicalizefallbacklocal") {
            Ok(Self::CanonicalizeFallbackLocal)
        } else if s.eq_ignore_ascii_case("canonicalizehostname") {
            Ok(Self::CanonicalizeHostname)
        } else if s.eq_ignore_ascii_case("canonicalizemaxdots") {
            Ok(Self::CanonicalizeMaxDots)
        } else if s.eq_ignore_ascii_case("canonicalizepermittedcnames") {
            Ok(Self::CanonicalizePermittedCNAMEs)
        } else if s.eq_ignore_ascii_case("casignaturealgorithms") {
            Ok(Self::CASignatureAlgorithms)
        } else if s.eq_ignore_ascii_case("certificatefile") {
            Ok(Self::CertificateFile)
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
        } else if s.eq_ignore_ascii_case("controlpersist") {
            Ok(Self::ControlPersist)
        } else if s.eq_ignore_ascii_case("dynamicforward") {
            Ok(Self::DynamicForward)
        } else if s.eq_ignore_ascii_case("enablesshkeysign") {
            Ok(Self::EnableSSHKeysign)
        } else if s.eq_ignore_ascii_case("escapechar") {
            Ok(Self::EscapeChar)
        } else if s.eq_ignore_ascii_case("exitonforwardfailure") {
            Ok(Self::ExitOnForwardFailure)
        } else if s.eq_ignore_ascii_case("fingerprinthash") {
            Ok(Self::FingerprintHash)
        } else if s.eq_ignore_ascii_case("forkafterauthentication") {
            Ok(Self::ForkAfterAuthentication)
        } else if s.eq_ignore_ascii_case("forwardagent") {
            Ok(Self::ForwardAgent)
        } else if s.eq_ignore_ascii_case("forwardx11") {
            Ok(Self::ForwardX11)
        } else if s.eq_ignore_ascii_case("forwardx11timeout") {
            Ok(Self::ForwardX11Timeout)
        } else if s.eq_ignore_ascii_case("forwardx11trusted") {
            Ok(Self::ForwardX11Trusted)
        } else if s.eq_ignore_ascii_case("gatewayports") {
            Ok(Self::GatewayPorts)
        } else if s.eq_ignore_ascii_case("globalknownhostsfile") {
            Ok(Self::GlobalKnownHostsFile)
        } else if s.eq_ignore_ascii_case("gssapiauthentication") {
            Ok(Self::GSSAPIAuthentication)
        } else if s.eq_ignore_ascii_case("gssapiclientidentity") {
            Ok(Self::GSSAPIClientIdentity)
        } else if s.eq_ignore_ascii_case("gssapidelegatecredentials") {
            Ok(Self::GSSAPIDelegateCredentials)
        } else if s.eq_ignore_ascii_case("gssapikeyexchange") {
            Ok(Self::GSSAPIKeyExchange)
        } else if s.eq_ignore_ascii_case("gssapirenewalforcesrekey") {
            Ok(Self::GSSAPIRenewalForcesRekey)
        } else if s.eq_ignore_ascii_case("gssapitrustdns") {
            Ok(Self::GSSAPITrustDns)
        } else if s.eq_ignore_ascii_case("hashknownhosts") {
            Ok(Self::HashKnownHosts)
        } else if s.eq_ignore_ascii_case("hostbasedacceptedalgorithms") {
            Ok(Self::HostbasedAcceptedAlgorithms)
        } else if s.eq_ignore_ascii_case("hostbasedauthentication") {
            Ok(Self::HostbasedAuthentication)
        } else if s.eq_ignore_ascii_case("hostkeyalgorithms") {
            Ok(Self::HostKeyAlgorithms)
        } else if s.eq_ignore_ascii_case("hostkeyalias") {
            Ok(Self::HostKeyAlias)
        } else if s.eq_ignore_ascii_case("hostname") {
            Ok(Self::Hostname)
        } else if s.eq_ignore_ascii_case("hostname") {
            Ok(Self::HostName)
        } else if s.eq_ignore_ascii_case("identitiesonly") {
            Ok(Self::IdentitiesOnly)
        } else if s.eq_ignore_ascii_case("identityagent") {
            Ok(Self::IdentityAgent)
        } else if s.eq_ignore_ascii_case("identityfile") {
            Ok(Self::IdentityFile)
        } else if s.eq_ignore_ascii_case("ignoreunknown") {
            Ok(Self::IgnoreUnknown)
        } else if s.eq_ignore_ascii_case("include") {
            Ok(Self::Include)
        } else if s.eq_ignore_ascii_case("ipqos") {
            Ok(Self::IPQoS)
        } else if s.eq_ignore_ascii_case("kbdinteractiveauthentication") {
            Ok(Self::KbdInteractiveAuthentication)
        } else if s.eq_ignore_ascii_case("kbdinteractivedevices") {
            Ok(Self::KbdInteractiveDevices)
        } else if s.eq_ignore_ascii_case("kexalgorithms") {
            Ok(Self::KexAlgorithms)
        } else if s.eq_ignore_ascii_case("knownhostscommand") {
            Ok(Self::KnownHostsCommand)
        } else if s.eq_ignore_ascii_case("localcommand") {
            Ok(Self::LocalCommand)
        } else if s.eq_ignore_ascii_case("localforward") {
            Ok(Self::LocalForward)
        } else if s.eq_ignore_ascii_case("loglevel") {
            Ok(Self::LogLevel)
        } else if s.eq_ignore_ascii_case("logverbose") {
            Ok(Self::LogVerbose)
        } else if s.eq_ignore_ascii_case("macs") {
            Ok(Self::MACs)
        } else if s.eq_ignore_ascii_case("match") {
            Ok(Self::Match)
        } else if s.eq_ignore_ascii_case("nohostauthenticationforlocalhost") {
            Ok(Self::NoHostAuthenticationForLocalhost)
        } else if s.eq_ignore_ascii_case("numberofpasswordprompts") {
            Ok(Self::NumberOfPasswordPrompts)
        } else if s.eq_ignore_ascii_case("passwordauthentication") {
            Ok(Self::PasswordAuthentication)
        } else if s.eq_ignore_ascii_case("permitlocalcommand") {
            Ok(Self::PermitLocalCommand)
        } else if s.eq_ignore_ascii_case("permitremoteopen") {
            Ok(Self::PermitRemoteOpen)
        } else if s.eq_ignore_ascii_case("pkcs11provider") {
            Ok(Self::PKCS11Provider)
        } else if s.eq_ignore_ascii_case("port") {
            Ok(Self::Port)
        } else if s.eq_ignore_ascii_case("preferredauthentications") {
            Ok(Self::PreferredAuthentications)
        } else if s.eq_ignore_ascii_case("protocol") {
            Ok(Self::Protocol)
        } else if s.eq_ignore_ascii_case("proxycommand") {
            Ok(Self::ProxyCommand)
        } else if s.eq_ignore_ascii_case("proxyjump") {
            Ok(Self::ProxyJump)
        } else if s.eq_ignore_ascii_case("proxyusefdpass") {
            Ok(Self::ProxyUseFdpass)
        } else if s.eq_ignore_ascii_case("pubkeyacceptedalgorithms") {
            Ok(Self::PubkeyAcceptedAlgorithms)
        } else if s.eq_ignore_ascii_case("pubkeyauthentication") {
            Ok(Self::PubkeyAuthentication)
        } else if s.eq_ignore_ascii_case("rekeylimit") {
            Ok(Self::RekeyLimit)
        } else if s.eq_ignore_ascii_case("remotecommand") {
            Ok(Self::RemoteCommand)
        } else if s.eq_ignore_ascii_case("remoteforward") {
            Ok(Self::RemoteForward)
        } else if s.eq_ignore_ascii_case("requesttty") {
            Ok(Self::RequestTTY)
        } else if s.eq_ignore_ascii_case("revokedhostkeys") {
            Ok(Self::RevokedHostKeys)
        } else if s.eq_ignore_ascii_case("rhostsrsaauthentication") {
            Ok(Self::RhostsRSAAuthentication)
        } else if s.eq_ignore_ascii_case("rsaauthentication") {
            Ok(Self::RSAAuthentication)
        } else if s.eq_ignore_ascii_case("securitykeyprovider") {
            Ok(Self::SecurityKeyProvider)
        } else if s.eq_ignore_ascii_case("sendenv") {
            Ok(Self::SendEnv)
        } else if s.eq_ignore_ascii_case("serveralivecountmax") {
            Ok(Self::ServerAliveCountMax)
        } else if s.eq_ignore_ascii_case("serveraliveinterval") {
            Ok(Self::ServerAliveInterval)
        } else if s.eq_ignore_ascii_case("sessiontype") {
            Ok(Self::SessionType)
        } else if s.eq_ignore_ascii_case("setenv") {
            Ok(Self::SetEnv)
        } else if s.eq_ignore_ascii_case("smartcarddevice") {
            Ok(Self::SmartcardDevice)
        } else if s.eq_ignore_ascii_case("stdinnull") {
            Ok(Self::StdinNull)
        } else if s.eq_ignore_ascii_case("streamlocalbindmask") {
            Ok(Self::StreamLocalBindMask)
        } else if s.eq_ignore_ascii_case("streamlocalbindunlink") {
            Ok(Self::StreamLocalBindUnlink)
        } else if s.eq_ignore_ascii_case("stricthostkeychecking") {
            Ok(Self::StrictHostKeyChecking)
        } else if s.eq_ignore_ascii_case("syslogfacility") {
            Ok(Self::SyslogFacility)
        } else if s.eq_ignore_ascii_case("tcpkeepalive") {
            Ok(Self::TCPKeepAlive)
        } else if s.eq_ignore_ascii_case("tunnel") {
            Ok(Self::Tunnel)
        } else if s.eq_ignore_ascii_case("tunneldevice") {
            Ok(Self::TunnelDevice)
        } else if s.eq_ignore_ascii_case("updatehostkeys") {
            Ok(Self::UpdateHostKeys)
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
        } else if s.eq_ignore_ascii_case("pubkeyacceptedkeytypes") {
            Ok(Self::PubkeyAcceptedKeyTypes)
        } else if s.eq_ignore_ascii_case("acceptenv") {
            Ok(Self::AcceptEnv)
        } else if s.eq_ignore_ascii_case("allowagentforwarding") {
            Ok(Self::AllowAgentForwarding)
        } else if s.eq_ignore_ascii_case("allowgroups") {
            Ok(Self::AllowGroups)
        } else if s.eq_ignore_ascii_case("allowstreamlocalforwarding") {
            Ok(Self::AllowStreamLocalForwarding)
        } else if s.eq_ignore_ascii_case("allowtcpforwarding") {
            Ok(Self::AllowTcpForwarding)
        } else if s.eq_ignore_ascii_case("allowusers") {
            Ok(Self::AllowUsers)
        } else if s.eq_ignore_ascii_case("authenticationmethods") {
            Ok(Self::AuthenticationMethods)
        } else if s.eq_ignore_ascii_case("authorizedkeyscommand") {
            Ok(Self::AuthorizedKeysCommand)
        } else if s.eq_ignore_ascii_case("authorizedkeyscommanduser") {
            Ok(Self::AuthorizedKeysCommandUser)
        } else if s.eq_ignore_ascii_case("authorizedkeysfile") {
            Ok(Self::AuthorizedKeysFile)
        } else if s.eq_ignore_ascii_case("authorizedprincipalscommand") {
            Ok(Self::AuthorizedPrincipalsCommand)
        } else if s.eq_ignore_ascii_case("authorizedprincipalscommanduser") {
            Ok(Self::AuthorizedPrincipalsCommandUser)
        } else if s.eq_ignore_ascii_case("authorizedprincipalsfile") {
            Ok(Self::AuthorizedPrincipalsFile)
        } else if s.eq_ignore_ascii_case("banner") {
            Ok(Self::Banner)
        } else if s.eq_ignore_ascii_case("chrootdirectory") {
            Ok(Self::ChrootDirectory)
        } else if s.eq_ignore_ascii_case("clientalivecountmax") {
            Ok(Self::ClientAliveCountMax)
        } else if s.eq_ignore_ascii_case("clientaliveinterval") {
            Ok(Self::ClientAliveInterval)
        } else if s.eq_ignore_ascii_case("denygroups") {
            Ok(Self::DenyGroups)
        } else if s.eq_ignore_ascii_case("denyusers") {
            Ok(Self::DenyUsers)
        } else if s.eq_ignore_ascii_case("disableforwarding") {
            Ok(Self::DisableForwarding)
        } else if s.eq_ignore_ascii_case("exposeauthinfo") {
            Ok(Self::ExposeAuthInfo)
        } else if s.eq_ignore_ascii_case("forcecommand") {
            Ok(Self::ForceCommand)
        } else if s.eq_ignore_ascii_case("gssapicleanupcredentials") {
            Ok(Self::GSSAPICleanupCredentials)
        } else if s.eq_ignore_ascii_case("gssapistrictacceptorcheck") {
            Ok(Self::GSSAPIStrictAcceptorCheck)
        } else if s.eq_ignore_ascii_case("hostbasedacceptedkeytypes") {
            Ok(Self::HostbasedAcceptedKeyTypes)
        } else if s.eq_ignore_ascii_case("hostbasedusesnamefrompacketonly") {
            Ok(Self::HostbasedUsesNameFromPacketOnly)
        } else if s.eq_ignore_ascii_case("hostcertificate") {
            Ok(Self::HostCertificate)
        } else if s.eq_ignore_ascii_case("hostkey") {
            Ok(Self::HostKey)
        } else if s.eq_ignore_ascii_case("hostkeyagent") {
            Ok(Self::HostKeyAgent)
        } else if s.eq_ignore_ascii_case("ignorerhosts") {
            Ok(Self::IgnoreRhosts)
        } else if s.eq_ignore_ascii_case("ignoreuserknownhosts") {
            Ok(Self::IgnoreUserKnownHosts)
        } else if s.eq_ignore_ascii_case("kerberosauthentication") {
            Ok(Self::KerberosAuthentication)
        } else if s.eq_ignore_ascii_case("kerberosgetafstoken") {
            Ok(Self::KerberosGetAFSToken)
        } else if s.eq_ignore_ascii_case("kerberosorlocalpasswd") {
            Ok(Self::KerberosOrLocalPasswd)
        } else if s.eq_ignore_ascii_case("kerberosticketcleanup") {
            Ok(Self::KerberosTicketCleanup)
        } else if s.eq_ignore_ascii_case("listenaddress") {
            Ok(Self::ListenAddress)
        } else if s.eq_ignore_ascii_case("logingracetime") {
            Ok(Self::LoginGraceTime)
        } else if s.eq_ignore_ascii_case("maxauthtries") {
            Ok(Self::MaxAuthTries)
        } else if s.eq_ignore_ascii_case("maxsessions") {
            Ok(Self::MaxSessions)
        } else if s.eq_ignore_ascii_case("maxstartups") {
            Ok(Self::MaxStartups)
        } else if s.eq_ignore_ascii_case("permitemptypasswords") {
            Ok(Self::PermitEmptyPasswords)
        } else if s.eq_ignore_ascii_case("permitlisten") {
            Ok(Self::PermitListen)
        } else if s.eq_ignore_ascii_case("permitopen") {
            Ok(Self::PermitOpen)
        } else if s.eq_ignore_ascii_case("permitrootlogin") {
            Ok(Self::PermitRootLogin)
        } else if s.eq_ignore_ascii_case("permittty") {
            Ok(Self::PermitTTY)
        } else if s.eq_ignore_ascii_case("permittunnel") {
            Ok(Self::PermitTunnel)
        } else if s.eq_ignore_ascii_case("permituserenvironment") {
            Ok(Self::PermitUserEnvironment)
        } else if s.eq_ignore_ascii_case("permituserrc") {
            Ok(Self::PermitUserRC)
        } else if s.eq_ignore_ascii_case("pidfile") {
            Ok(Self::PidFile)
        } else if s.eq_ignore_ascii_case("printlastlog") {
            Ok(Self::PrintLastLog)
        } else if s.eq_ignore_ascii_case("printmotd") {
            Ok(Self::PrintMotd)
        } else if s.eq_ignore_ascii_case("revokedkeys") {
            Ok(Self::RevokedKeys)
        } else if s.eq_ignore_ascii_case("rdomain") {
            Ok(Self::RDomain)
        } else if s.eq_ignore_ascii_case("strictmodes") {
            Ok(Self::StrictModes)
        } else if s.eq_ignore_ascii_case("subsystem") {
            Ok(Self::Subsystem)
        } else if s.eq_ignore_ascii_case("trustedusercakeys") {
            Ok(Self::TrustedUserCAKeys)
        } else if s.eq_ignore_ascii_case("useblacklist") {
            Ok(Self::UseBlacklist)
        } else if s.eq_ignore_ascii_case("usedns") {
            Ok(Self::UseDNS)
        } else if s.eq_ignore_ascii_case("usepam") {
            Ok(Self::UsePAM)
        } else if s.eq_ignore_ascii_case("versionaddendum") {
            Ok(Self::VersionAddendum)
        } else if s.eq_ignore_ascii_case("x11displayoffset") {
            Ok(Self::X11DisplayOffset)
        } else if s.eq_ignore_ascii_case("x11forwarding") {
            Ok(Self::X11Forwarding)
        } else if s.eq_ignore_ascii_case("x11uselocalhost") {
            Ok(Self::X11UseLocalhost)
        } else {
            Err(ConfigError::SshOptionUnknown { key: s.to_string() })
        }
    }
}

impl fmt::Display for SshOptionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Host => write!(f, "Host"),
            Self::AddKeysToAgent => write!(f, "AddKeysToAgent"),
            Self::AddressFamily => write!(f, "AddressFamily"),
            Self::BatchMode => write!(f, "BatchMode"),
            Self::BindAddress => write!(f, "BindAddress"),
            Self::BindInterface => write!(f, "BindInterface"),
            Self::CanonicalDomains => write!(f, "CanonicalDomains"),
            Self::CanonicalizeFallbackLocal => write!(f, "CanonicalizeFallbackLocal"),
            Self::CanonicalizeHostname => write!(f, "CanonicalizeHostname"),
            Self::CanonicalizeMaxDots => write!(f, "CanonicalizeMaxDots"),
            Self::CanonicalizePermittedCNAMEs => write!(f, "CanonicalizePermittedCNAMEs"),
            Self::CASignatureAlgorithms => write!(f, "CASignatureAlgorithms"),
            Self::CertificateFile => write!(f, "CertificateFile"),
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
            Self::ControlPersist => write!(f, "ControlPersist"),
            Self::DynamicForward => write!(f, "DynamicForward"),
            Self::EnableSSHKeysign => write!(f, "EnableSSHKeysign"),
            Self::EscapeChar => write!(f, "EscapeChar"),
            Self::ExitOnForwardFailure => write!(f, "ExitOnForwardFailure"),
            Self::FingerprintHash => write!(f, "FingerprintHash"),
            Self::ForkAfterAuthentication => write!(f, "ForkAfterAuthentication"),
            Self::ForwardAgent => write!(f, "ForwardAgent"),
            Self::ForwardX11 => write!(f, "ForwardX11"),
            Self::ForwardX11Timeout => write!(f, "ForwardX11Timeout"),
            Self::ForwardX11Trusted => write!(f, "ForwardX11Trusted"),
            Self::GatewayPorts => write!(f, "GatewayPorts"),
            Self::GlobalKnownHostsFile => write!(f, "GlobalKnownHostsFile"),
            Self::GSSAPIAuthentication => write!(f, "GSSAPIAuthentication"),
            Self::GSSAPIClientIdentity => write!(f, "GSSAPIClientIdentity"),
            Self::GSSAPIDelegateCredentials => write!(f, "GSSAPIDelegateCredentials"),
            Self::GSSAPIKeyExchange => write!(f, "GSSAPIKeyExchange"),
            Self::GSSAPIRenewalForcesRekey => write!(f, "GSSAPIRenewalForcesRekey"),
            Self::GSSAPITrustDns => write!(f, "GSSAPITrustDns"),
            Self::HashKnownHosts => write!(f, "HashKnownHosts"),
            Self::HostbasedAcceptedAlgorithms => write!(f, "HostbasedAcceptedAlgorithms"),
            Self::HostbasedAuthentication => write!(f, "HostbasedAuthentication"),
            Self::HostKeyAlgorithms => write!(f, "HostKeyAlgorithms"),
            Self::HostKeyAlias => write!(f, "HostKeyAlias"),
            Self::Hostname => write!(f, "Hostname"),
            Self::HostName => write!(f, "HostName"),
            Self::IdentitiesOnly => write!(f, "IdentitiesOnly"),
            Self::IdentityAgent => write!(f, "IdentityAgent"),
            Self::IdentityFile => write!(f, "IdentityFile"),
            Self::IgnoreUnknown => write!(f, "IgnoreUnknown"),
            Self::Include => write!(f, "Include"),
            Self::IPQoS => write!(f, "IPQoS"),
            Self::KbdInteractiveAuthentication => write!(f, "KbdInteractiveAuthentication"),
            Self::KbdInteractiveDevices => write!(f, "KbdInteractiveDevices"),
            Self::KexAlgorithms => write!(f, "KexAlgorithms"),
            Self::KnownHostsCommand => write!(f, "KnownHostsCommand"),
            Self::LocalCommand => write!(f, "LocalCommand"),
            Self::LocalForward => write!(f, "LocalForward"),
            Self::LogLevel => write!(f, "LogLevel"),
            Self::LogVerbose => write!(f, "LogVerbose"),
            Self::MACs => write!(f, "MACs"),
            Self::Match => write!(f, "Match"),
            Self::NoHostAuthenticationForLocalhost => write!(f, "NoHostAuthenticationForLocalhost"),
            Self::NumberOfPasswordPrompts => write!(f, "NumberOfPasswordPrompts"),
            Self::PasswordAuthentication => write!(f, "PasswordAuthentication"),
            Self::PermitLocalCommand => write!(f, "PermitLocalCommand"),
            Self::PermitRemoteOpen => write!(f, "PermitRemoteOpen"),
            Self::PKCS11Provider => write!(f, "PKCS11Provider"),
            Self::Port => write!(f, "Port"),
            Self::PreferredAuthentications => write!(f, "PreferredAuthentications"),
            Self::Protocol => write!(f, "Protocol"),
            Self::ProxyCommand => write!(f, "ProxyCommand"),
            Self::ProxyJump => write!(f, "ProxyJump"),
            Self::ProxyUseFdpass => write!(f, "ProxyUseFdpass"),
            Self::PubkeyAcceptedAlgorithms => write!(f, "PubkeyAcceptedAlgorithms"),
            Self::PubkeyAuthentication => write!(f, "PubkeyAuthentication"),
            Self::RekeyLimit => write!(f, "RekeyLimit"),
            Self::RemoteCommand => write!(f, "RemoteCommand"),
            Self::RemoteForward => write!(f, "RemoteForward"),
            Self::RequestTTY => write!(f, "RequestTTY"),
            Self::RevokedHostKeys => write!(f, "RevokedHostKeys"),
            Self::RhostsRSAAuthentication => write!(f, "RhostsRSAAuthentication"),
            Self::RSAAuthentication => write!(f, "RSAAuthentication"),
            Self::SecurityKeyProvider => write!(f, "SecurityKeyProvider"),
            Self::SendEnv => write!(f, "SendEnv"),
            Self::ServerAliveCountMax => write!(f, "ServerAliveCountMax"),
            Self::ServerAliveInterval => write!(f, "ServerAliveInterval"),
            Self::SessionType => write!(f, "SessionType"),
            Self::SetEnv => write!(f, "SetEnv"),
            Self::SmartcardDevice => write!(f, "SmartcardDevice"),
            Self::StdinNull => write!(f, "StdinNull"),
            Self::StreamLocalBindMask => write!(f, "StreamLocalBindMask"),
            Self::StreamLocalBindUnlink => write!(f, "StreamLocalBindUnlink"),
            Self::StrictHostKeyChecking => write!(f, "StrictHostKeyChecking"),
            Self::SyslogFacility => write!(f, "SyslogFacility"),
            Self::TCPKeepAlive => write!(f, "TCPKeepAlive"),
            Self::Tunnel => write!(f, "Tunnel"),
            Self::TunnelDevice => write!(f, "TunnelDevice"),
            Self::UpdateHostKeys => write!(f, "UpdateHostKeys"),
            Self::UsePrivilegedPort => write!(f, "UsePrivilegedPort"),
            Self::User => write!(f, "User"),
            Self::UserKnownHostsFile => write!(f, "UserKnownHostsFile"),
            Self::VerifyHostKeyDNS => write!(f, "VerifyHostKeyDNS"),
            Self::VisualHostKey => write!(f, "VisualHostKey"),
            Self::XAuthLocation => write!(f, "XAuthLocation"),
            Self::PubkeyAcceptedKeyTypes => write!(f, "PubkeyAcceptedKeyTypes"),
            Self::AcceptEnv => write!(f, "AcceptEnv"),
            Self::AllowAgentForwarding => write!(f, "AllowAgentForwarding"),
            Self::AllowGroups => write!(f, "AllowGroups"),
            Self::AllowStreamLocalForwarding => write!(f, "AllowStreamLocalForwarding"),
            Self::AllowTcpForwarding => write!(f, "AllowTcpForwarding"),
            Self::AllowUsers => write!(f, "AllowUsers"),
            Self::AuthenticationMethods => write!(f, "AuthenticationMethods"),
            Self::AuthorizedKeysCommand => write!(f, "AuthorizedKeysCommand"),
            Self::AuthorizedKeysCommandUser => write!(f, "AuthorizedKeysCommandUser"),
            Self::AuthorizedKeysFile => write!(f, "AuthorizedKeysFile"),
            Self::AuthorizedPrincipalsCommand => write!(f, "AuthorizedPrincipalsCommand"),
            Self::AuthorizedPrincipalsCommandUser => write!(f, "AuthorizedPrincipalsCommandUser"),
            Self::AuthorizedPrincipalsFile => write!(f, "AuthorizedPrincipalsFile"),
            Self::Banner => write!(f, "Banner"),
            Self::ChrootDirectory => write!(f, "ChrootDirectory"),
            Self::ClientAliveCountMax => write!(f, "ClientAliveCountMax"),
            Self::ClientAliveInterval => write!(f, "ClientAliveInterval"),
            Self::DenyGroups => write!(f, "DenyGroups"),
            Self::DenyUsers => write!(f, "DenyUsers"),
            Self::DisableForwarding => write!(f, "DisableForwarding"),
            Self::ExposeAuthInfo => write!(f, "ExposeAuthInfo"),
            Self::ForceCommand => write!(f, "ForceCommand"),
            Self::GSSAPICleanupCredentials => write!(f, "GSSAPICleanupCredentials"),
            Self::GSSAPIStrictAcceptorCheck => write!(f, "GSSAPIStrictAcceptorCheck"),
            Self::HostbasedAcceptedKeyTypes => write!(f, "HostbasedAcceptedKeyTypes"),
            Self::HostbasedUsesNameFromPacketOnly => write!(f, "HostbasedUsesNameFromPacketOnly"),
            Self::HostCertificate => write!(f, "HostCertificate"),
            Self::HostKey => write!(f, "HostKey"),
            Self::HostKeyAgent => write!(f, "HostKeyAgent"),
            Self::IgnoreRhosts => write!(f, "IgnoreRhosts"),
            Self::IgnoreUserKnownHosts => write!(f, "IgnoreUserKnownHosts"),
            Self::KerberosAuthentication => write!(f, "KerberosAuthentication"),
            Self::KerberosGetAFSToken => write!(f, "KerberosGetAFSToken"),
            Self::KerberosOrLocalPasswd => write!(f, "KerberosOrLocalPasswd"),
            Self::KerberosTicketCleanup => write!(f, "KerberosTicketCleanup"),
            Self::ListenAddress => write!(f, "ListenAddress"),
            Self::LoginGraceTime => write!(f, "LoginGraceTime"),
            Self::MaxAuthTries => write!(f, "MaxAuthTries"),
            Self::MaxSessions => write!(f, "MaxSessions"),
            Self::MaxStartups => write!(f, "MaxStartups"),
            Self::PermitEmptyPasswords => write!(f, "PermitEmptyPasswords"),
            Self::PermitListen => write!(f, "PermitListen"),
            Self::PermitOpen => write!(f, "PermitOpen"),
            Self::PermitRootLogin => write!(f, "PermitRootLogin"),
            Self::PermitTTY => write!(f, "PermitTTY"),
            Self::PermitTunnel => write!(f, "PermitTunnel"),
            Self::PermitUserEnvironment => write!(f, "PermitUserEnvironment"),
            Self::PermitUserRC => write!(f, "PermitUserRC"),
            Self::PidFile => write!(f, "PidFile"),
            Self::PrintLastLog => write!(f, "PrintLastLog"),
            Self::PrintMotd => write!(f, "PrintMotd"),
            Self::RevokedKeys => write!(f, "RevokedKeys"),
            Self::RDomain => write!(f, "RDomain"),
            Self::StrictModes => write!(f, "StrictModes"),
            Self::Subsystem => write!(f, "Subsystem"),
            Self::TrustedUserCAKeys => write!(f, "TrustedUserCAKeys"),
            Self::UseBlacklist => write!(f, "UseBlacklist"),
            Self::UseDNS => write!(f, "UseDNS"),
            Self::UsePAM => write!(f, "UsePAM"),
            Self::VersionAddendum => write!(f, "VersionAddendum"),
            Self::X11DisplayOffset => write!(f, "X11DisplayOffset"),
            Self::X11Forwarding => write!(f, "X11Forwarding"),
            Self::X11UseLocalhost => write!(f, "X11UseLocalhost"),
        }
    }
}
