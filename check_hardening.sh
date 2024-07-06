#!/bin/bash

# Script de Verificação de Hardening Generico para Linux
# Autor: Gabriel D. Lopes (CoderDias)
# Créditos: Desenvolvido com base em melhores práticas de segurança e referências da comunidade de segurança de TI.
# Data: 17/05/2019
# Descrição: Este script realiza uma verificação completa de hardening em um sistema Linux, exibindo os resultados de forma fácil de entender.
# Uso: Execute este script como root ou com permissões sudo.

check_status() {
    local description="$1"
    local command="$2"
    echo "=== $description ==="
    echo "Comando: $command"
    result=$(eval "$command")
	
    if [[ -z "$result" ]]; then
        echo "Status: NÃO CONFIGURADO"
    else
        echo "Status: CONFIGURADO"
        echo "Resultado: $result"
    fi
    echo "----------------------------------------"
}

# 1. Verificar se o SELinux está habilitado
check_status "SELinux habilitado" "getenforce"

# 2. Verificar se o firewall está ativo
check_status "Firewall ativo" "sudo ufw status | grep Status"

# 3. Verificar se as senhas expiram
check_status "Senhas expiram" "sudo chage -l $(whoami) | grep 'Password expires'"

# 4. Verificar se há usuários sem senha
check_status "Usuários sem senha" "sudo awk -F: '($2 == \"\") {print}' /etc/shadow"

# 5. Verificar se root só pode logar localmente
check_status "Root só pode logar localmente" "sudo grep '^tty1$' /etc/securetty"

# 6. Verificar se a auditoria está configurada
check_status "Auditoria configurada" "sudo auditctl -s"

# 7. Verificar se há atualizações pendentes
check_status "Atualizações pendentes" "sudo apt list --upgradable"

# 8. Verificar permissões no arquivo /etc/passwd
check_status "Permissões em /etc/passwd" "ls -l /etc/passwd"

# 9. Verificar permissões no arquivo /etc/shadow
check_status "Permissões em /etc/shadow" "ls -l /etc/shadow"

# 10. Verificar se há processos em execução como root
check_status "Processos em execução como root" "ps -U root -u root u"

# 11. Verificar se o SSH root login está desabilitado
check_status "SSH root login desabilitado" "sudo grep '^PermitRootLogin' /etc/ssh/sshd_config"

# 12. Verificar se há usuários com UID 0 além do root
check_status "Usuários com UID 0" "awk -F: '($3 == 0) {print}' /etc/passwd"

# 13. Verificar se as partições sensíveis estão separadas
check_status "Partições separadas" "mount | grep -E '\s/(home|tmp|var|var/log)\s'"

# 14. Verificar se há serviços desnecessários em execução
check_status "Serviços desnecessários em execução" "systemctl list-units --type=service --state=running"

# 15. Verificar se a senha do GRUB está configurada
check_status "Senha do GRUB configurada" "sudo grep '^set superusers' /boot/grub/grub.cfg"

# 16. Verificar se o IPv6 está desativado se não for necessário
check_status "IPv6 desativado" "sudo sysctl -a | grep net.ipv6.conf.all.disable_ipv6"

# 17. Verificar se o redirecionamento de pacotes IP está desabilitado
check_status "Redirecionamento de pacotes IP desabilitado" "sudo sysctl net.ipv4.ip_forward"

# 18. Verificar se o encaminhamento de pacotes IPv6 está desabilitado
check_status "Encaminhamento de pacotes IPv6 desabilitado" "sudo sysctl net.ipv6.conf.all.forwarding"

# 19. Verificar se o ICMP broadcast está desativado
check_status "ICMP broadcast desativado" "sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts"

# 20. Verificar se há restrição de mensagens de erro ICMP
check_status "Restrições de mensagens de erro ICMP" "sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses"

# 21. Verificar se o logging de pacotes suspeitos está habilitado
check_status "Logging de pacotes suspeitos habilitado" "sudo sysctl net.ipv4.conf.all.log_martians"

# 22. Verificar se a proteção contra SYN flood está habilitada
check_status "Proteção contra SYN flood habilitada" "sudo sysctl net.ipv4.tcp_syncookies"

# 23. Verificar se há limite de taxa para conexões de entrada
check_status "Limite de taxa para conexões de entrada" "sudo sysctl net.ipv4.tcp_max_syn_backlog"

# 24. Verificar se o roteamento de origem está desativado
check_status "Roteamento de origem desativado" "sudo sysctl net.ipv4.conf.all.accept_source_route"

# 25. Verificar se a aceitação de redirecionamentos ICMP está desativada
check_status "Aceitação de redirecionamentos ICMP desativada" "sudo sysctl net.ipv4.conf.all.accept_redirects"

# 26. Verificar se a aceitação de redirecionamentos ICMP IPv6 está desativada
check_status "Aceitação de redirecionamentos ICMP IPv6 desativada" "sudo sysctl net.ipv6.conf.all.accept_redirects"

# 27. Verificar se a aceitação de pacotes de broadcast está desativada
check_status "Aceitação de pacotes de broadcast desativada" "sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts"

# 28. Verificar se o logging de pacotes de broadcast está habilitado
check_status "Logging de pacotes de broadcast habilitado" "sudo sysctl net.ipv4.conf.all.log_martians"

# 29. Verificar se a proteção contra spoofing de endereço IP está habilitada
check_status "Proteção contra spoofing de IP habilitada" "sudo sysctl net.ipv4.conf.all.rp_filter"

# 30. Verificar se o bloqueio de IP inválido está habilitado
check_status "Bloqueio de IP inválido habilitado" "sudo sysctl net.ipv4.conf.all.accept_source_route"

# 31. Verificar se o kernel está configurado para reforçar a segurança de pacotes
check_status "Reforço de segurança de pacotes" "sudo sysctl net.ipv4.conf.all.accept_redirects"

# 32. Verificar se as atualizações automáticas estão configuradas
check_status "Atualizações automáticas configuradas" "sudo systemctl status apt-daily-upgrade.timer"

# 33. Verificar se o modo de kernel lockdown está habilitado
check_status "Kernel lockdown habilitado" "sudo cat /sys/kernel/security/lockdown"

# 34. Verificar se o carregamento de módulos desnecessários está desabilitado
check_status "Carregamento de módulos desnecessários desabilitado" "sudo grep -E '^\s*blacklist' /etc/modprobe.d/*.conf"

# 35. Verificar se a proteção contra buffer overflow está habilitada
check_status "Proteção contra buffer overflow habilitada" "sudo dmesg | grep NX"

# 36. Verificar se a compilação de código com stack protector está habilitada
check_status "Stack protector habilitado" "gcc -v 2>&1 | grep stack-protector"

# 37. Verificar se a execução de binários na stack está desabilitada
check_status "Execução de binários na stack desabilitada" "sudo sysctl -a | grep kernel.exec-shield"

# 38. Verificar se a proteção de memória está habilitada
check_status "Proteção de memória habilitada" "sudo sysctl -a | grep kernel.randomize_va_space"

# 39. Verificar se o AppArmor está habilitado
check_status "AppArmor habilitado" "sudo aa-status"

# 40. Verificar se o auditd está instalado e habilitado
check_status "auditd instalado e habilitado" "sudo systemctl status auditd"

# 41. Verificar se o LSM (Linux Security Module) está habilitado
check_status "LSM habilitado" "sudo cat /sys/kernel/security/lsm"

# 42. Verificar se a auditoria de login está habilitada
check_status "Auditoria de login habilitada" "sudo grep 'session required pam_tty_audit.so' /etc/pam.d/login"

# 43. Verificar se a política de senha forte está configurada
check_status "Política de senha forte configurada" "sudo grep pam_pwquality.so /etc/pam.d/common-password"

# 44. Verificar se há limitação de tentativas de login
check_status "Limitação de tentativas de login" "sudo grep pam_tally2 /etc/pam.d/common-auth"

# 45. Verificar se o root tem um shell de login válido
check_status "Root com shell de login válido" "sudo grep '^root' /etc/passwd | grep -E '/bin/bash|/bin/sh|/bin/dash|/bin/zsh'"

# 46. Verificar se o login remoto está restrito
check_status "Login remoto restrito" "sudo grep -E 'sshd:.*ALL' /etc/hosts.deny"

# 47. Verificar se o serviço de compartilhamento NFS está desativado
check_status "Serviço de NFS desativado" "sudo systemctl is-active nfs-kernel-server"

# 48. Verificar se o serviço de FTP está desativado
check_status "Serviço de FTP desativado" "sudo systemctl is-active vsftpd"

# 49. Verificar se o serviço de SMB/CIFS está desativado
check_status "Serviço de SMB/CIFS desativado" "sudo systemctl is-active smbd"

# 50. Verificar se o serviço de Telnet está desativado
check_status "Serviço de Telnet desativado" "sudo systemctl is-active telnet.socket"

# 51. Verificar se o serviço de HTTP está desativado se não for necessário
check_status "Serviço de HTTP desativado" "sudo systemctl is-active apache2"

# 52. Verificar se o serviço de SNMP está desativado se não for necessário
check_status "Serviço de SNMP desativado" "sudo systemctl is-active snmpd"

# 53. Verificar se o serviço de MySQL está desativado se não for necessário
check_status "Serviço de MySQL desativado" "sudo systemctl is-active mysql"

# 54. Verificar se o serviço de PostgreSQL está desativado se não for necessário
check_status "Serviço de PostgreSQL desativado" "sudo systemctl is-active postgresql"

# 55. Verificar se o serviço de Dovecot está desativado se não for necessário
check_status "Serviço de Dovecot desativado" "sudo systemctl is-active dovecot"

# 56. Verificar se o serviço de Sendmail está desativado se não for necessário
check_status "Serviço de Sendmail desativado" "sudo systemctl is-active sendmail"

# 57. Verificar se o serviço de CUPS está desativado se não for necessário
check_status "Serviço de CUPS desativado" "sudo systemctl is-active cups"

# 58. Verificar se o serviço de Avahi está desativado
check_status "Serviço de Avahi desativado" "sudo systemctl is-active avahi-daemon"

# 59. Verificar se o serviço de DHCP está desativado
check_status "Serviço de DHCP desativado" "sudo systemctl is-active isc-dhcp-server"

# 60. Verificar se o serviço de NTP está configurado corretamente
check_status "Serviço de NTP configurado corretamente" "sudo systemctl is-active ntp"

# 61. Verificar se o serviço de Cron está habilitado
check_status "Serviço de Cron habilitado" "sudo systemctl is-active cron"

# 62. Verificar se o serviço de Syslog está habilitado
check_status "Serviço de Syslog habilitado" "sudo systemctl is-active rsyslog"

# 63. Verificar se o serviço de Logrotate está configurado
check_status "Serviço de Logrotate configurado" "sudo systemctl is-active logrotate"

# 64. Verificar se o serviço de SSH está configurado para usar apenas protocolo 2
check_status "SSH configurado para usar apenas protocolo 2" "sudo grep '^Protocol' /etc/ssh/sshd_config"

# 65. Verificar se o serviço de SSH está configurado para usar apenas ciphers fortes
check_status "SSH configurado para usar ciphers fortes" "sudo grep '^Ciphers' /etc/ssh/sshd_config"

# 66. Verificar se o serviço de SSH está configurado para usar apenas MACs fortes
check_status "SSH configurado para usar MACs fortes" "sudo grep '^MACs' /etc/ssh/sshd_config"

# 67. Verificar se o serviço de SSH está configurado para limitar o número de conexões
check_status "SSH configurado para limitar o número de conexões" "sudo grep '^MaxSessions' /etc/ssh/sshd_config"

# 68. Verificar se o serviço de SSH está configurado para limitar o número de tentativas de autenticação
check_status "SSH configurado para limitar tentativas de autenticação" "sudo grep '^MaxAuthTries' /etc/ssh/sshd_config"

# 69. Verificar se o serviço de SSH está configurado para usar apenas chaves públicas
check_status "SSH configurado para usar apenas chaves públicas" "sudo grep '^PasswordAuthentication no' /etc/ssh/sshd_config"

# 70. Verificar se o serviço de SSH está configurado para desconectar sessões inativas
check_status "SSH configurado para desconectar sessões inativas" "sudo grep '^ClientAliveInterval' /etc/ssh/sshd_config"

# 71. Verificar se o serviço de SSH está configurado para registrar logins
check_status "SSH configurado para registrar logins" "sudo grep '^SyslogFacility' /etc/ssh/sshd_config"

# 72. Verificar se o serviço de SSH está configurado para limitar o uso de root
check_status "SSH configurado para limitar o uso de root" "sudo grep '^PermitRootLogin' /etc/ssh/sshd_config"

# 73. Verificar se o serviço de SSH está configurado para usar uma porta não padrão
check_status "SSH configurado para usar uma porta não padrão" "sudo grep '^Port' /etc/ssh/sshd_config"

# 74. Verificar se há permissões seguras no arquivo de configuração do SSH
check_status "Permissões seguras no arquivo de configuração do SSH" "ls -l /etc/ssh/sshd_config"

# 75. Verificar se a configuração do PAM está correta
check_status "Configuração do PAM correta" "sudo grep -E '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su"

# 76. Verificar se há permissões seguras nos arquivos de configuração do PAM
check_status "Permissões seguras nos arquivos do PAM" "ls -l /etc/pam.d/"

# 77. Verificar se o sysctl.conf está configurado corretamente
check_status "sysctl.conf configurado corretamente" "grep -E '^(net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.log_martians|net.ipv4.conf.all.rp_filter|net.ipv4.conf.all.accept_source_route|net.ipv4.conf.default.accept_redirects|net.ipv4.icmp_echo_ignore_broadcasts|net.ipv4.icmp_ignore_bogus_error_responses|net.ipv4.tcp_syncookies)' /etc/sysctl.conf"

# 78. Verificar se há permissões seguras no arquivo sysctl.conf
check_status "Permissões seguras no arquivo sysctl.conf" "ls -l /etc/sysctl.conf"

# 79. Verificar se o sistema de arquivos está configurado corretamente
check_status "Sistema de arquivos configurado corretamente" "mount | grep -E 'nodev|nosuid|noexec'"

# 80. Verificar se há permissões seguras nos arquivos de configuração do sistema de arquivos
check_status "Permissões seguras nos arquivos do sistema de arquivos" "ls -l /etc/fstab"

# 81. Verificar se o serviço de journald está habilitado
check_status "Serviço de journald habilitado" "sudo systemctl is-active systemd-journald"

# 82. Verificar se a rotação de logs está configurada para o journald
check_status "Rotação de logs configurada para journald" "sudo grep 'SystemMaxUse=' /etc/systemd/journald.conf"

# 83. Verificar se a rotação de logs está configurada para o rsyslog
check_status "Rotação de logs configurada para rsyslog" "sudo grep 'rotate' /etc/logrotate.d/rsyslog"

# 84. Verificar se o serviço de cron está configurado corretamente
check_status "Serviço de cron configurado corretamente" "sudo grep -E '^(root|ALL) ALL' /etc/cron.allow"

# 85. Verificar se o serviço de anacron está configurado corretamente
check_status "Serviço de anacron configurado corretamente" "sudo grep -E '^(root|ALL) ALL' /etc/anacrontab"

# 86. Verificar se o serviço de atd está configurado corretamente
check_status "Serviço de atd configurado corretamente" "sudo grep -E '^(root|ALL) ALL' /etc/at.allow"

# 87. Verificar se há permissões seguras nos arquivos de configuração do cron
check_status "Permissões seguras nos arquivos do cron" "ls -l /etc/cron*"

# 88. Verificar se o sistema está configurado para minimizar os tempos de inatividade
check_status "Sistema configurado para minimizar tempos de inatividade" "sudo grep -E '^(vm.dirty_background_ratio|vm.dirty_ratio)' /etc/sysctl.conf"

# 89. Verificar se há permissões seguras nos arquivos de configuração do logrotate
check_status "Permissões seguras nos arquivos do logrotate" "ls -l /etc/logrotate.d/"

# 90. Verificar se o sistema está configurado para forçar limites de recurso
check_status "Sistema configurado para forçar limites de recurso" "sudo grep -E '^(hard|soft)' /etc/security/limits.conf"

# 91. Verificar se o sistema está configurado para desativar contas inativas
check_status "Sistema configurado para desativar contas inativas" "sudo usermod -L $(sudo passwd -S | grep 'NP' | awk '{print $1}')"

# 92. Verificar se o sistema está configurado para bloquear contas após tentativas de login falhadas
check_status "Sistema configurado para bloquear contas após tentativas de login falhadas" "sudo grep pam_faillock.so /etc/pam.d/common-auth"

# 93. Verificar se há permissões seguras nos arquivos de configuração do PAM
check_status "Permissões seguras nos arquivos do PAM" "ls -l /etc/security/"

# 94. Verificar se há permissões seguras nos arquivos de configuração do auditd
check_status "Permissões seguras nos arquivos do auditd" "ls -l /etc/audit/"

# 95. Verificar se o sistema está configurado para restringir o acesso a terminais
check_status "Sistema configurado para restringir acesso a terminais" "sudo grep 'ALL' /etc/security/access.conf"

# 96. Verificar se há permissões seguras nos arquivos de configuração do acesso
check_status "Permissões seguras nos arquivos de configuração do acesso" "ls -l /etc/security/access.conf"

# 97. Verificar se o sistema está configurado para enviar alertas de segurança
check_status "Sistema configurado para enviar alertas de segurança" "sudo grep 'ACTION' /etc/aliases"

# 98. Verificar se há permissões seguras nos arquivos de configuração de aliases
check_status "Permissões seguras nos arquivos de configuração de aliases" "ls -l /etc/aliases"

# 99. Verificar se o sistema está configurado para sincronizar o tempo com servidores NTP
check_status "Sistema configurado para sincronizar o tempo com servidores NTP" "sudo systemctl is-active ntp"

# 100. Verificar se há permissões seguras nos arquivos de configuração do NTP
check_status "Permissões seguras nos arquivos de configuração do NTP" "ls -l /etc/ntp.conf"

echo "Verificação de hardening concluída."
