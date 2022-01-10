#！/bin/bash
# description: classified protection baseline change

#bootloader权限控制
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

#核心转储开启
echo '* hard core 0' >/etc/security/limits.d/60-hard-core.conf
echo '* hard core 0' >/etc/sysctl.d/60-hard-core.conf
sysctl -w fs.suid_dumpable=0

#开启地址空间布局随机化（ASLR）

echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/61-aslr.conf
sysctl -w kernel.randomize_va_space=2

#审核日志已满时禁用系统
[[ `grep 'space_left_action = email' /etc/audit/auditd.conf|wc -l` -lt 1 ]] && echo 'space_left_action = email' >/etc/audit/auditd.conf
[[ `grep 'action_mail_acct = root' /etc/audit/auditd.conf|wc -l` -lt 1 ]] && echo 'action_mail_acct = root' >/etc/audit/auditd.conf
[[ `grep 'admin_space_left_action = halt' /etc/audit/auditd.conf|wc -l` -lt 1 ]] && echo 'admin_space_left_action = halt' >/etc/audit/auditd.conf

#确保审核日志不会自动删除
[[ `grep 'max_log_file_action = keep_logs' /etc/audit/auditd.conf|wc -l` -lt 1 ]] && echo 'max_log_file_action = keep_logs' >/etc/audit/auditd.conf


#（sudoers）更改的收集
echo '-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-e 2
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
' >> /etc/audit/rules.d/audit.rules

echo '-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-e 2
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
' >>/etc/audit/audit.rules

#sshd配置调整
[[ `grep -P '^\s*ClientAliveInterval' /etc/ssh/sshd_config |wc -l` -lt 1  ]]&& sed -i '100a ClientAliveInterval 300' /etc/ssh/sshd_config ||sed -i 's/ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
[[ `grep -P '^\s*ClientAliveCountMax' /etc/ssh/sshd_config |wc -l` -lt 1  ]]&& sed -i '100a ClientAliveCountMax 0' /etc/ssh/sshd_config ||sed -i 's/ClientAliveCountMax.*/ClientAliveCountMax 0/'  /etc/ssh/sshd_config
[[ `grep -P '^\s*MaxAuthTries' /etc/ssh/sshd_config |wc -l` -lt 1  ]]&& sed  -i '40a MaxAuthTries 4' /etc/ssh/sshd_config ||sed -i 's/MaxAuthTries.*/MaxAuthTries 4/'  /etc/ssh/sshd_config
[[ `grep -P '^\s*PermitEmptyPasswords' /etc/ssh/sshd_config |wc -l` -lt  1  ]]&& sed  -i '65a PermitEmptyPasswords no' /etc/ssh/sshd_config ||sed -i 's/PermitEmptyPasswords.*/PermitEmptyPasswords no/'  /etc/ssh/sshd_config

#登录pam限制

[[ `grep -P '^\s*auth required pam_faillock.so preauth audit' /etc/pam.d/password-auth |wc -l` -lt 1  ]]&& sed  -i '9a auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/password-auth ||sed -i 's/auth required pam_faillock.so preauth audit.*/auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900/'  /etc/pam.d/password-auth
[[ `grep -P '^\s*auth required pam_faillock.so preauth audit' /etc/pam.d/system-auth |wc -l` -lt 1  ]]&& sed  -i '9a auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/system-auth ||sed -i 's/auth required pam_faillock.so preauth audit.*/auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900/'  /etc/pam.d/system-auth
sed -i '9a auth [success=1 default=bad] pam_unix.so' /etc/pam.d/password-auth  /etc/pam.d/system-auth
sed -i '9a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/password-auth /etc/pam.d/system-auth
sed -i '9a auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900' /etc/pam.d/password-auth  /etc/pam.d/system-auth

#修改umask
sed -i 's/umask 002/umask 007/'  /etc/bashrc /etc/profile /etc/profile.d/*.sh
sed -i 's/umask 022/umask 027/'  /etc/bashrc /etc/profile /etc/profile.d/*.sh

[[ `grep -P '^\s*TMOUT' /etc/bashrc |wc -l` -lt 1  ]]&& sed  -i '$a TMOUT=600' /etc/bashrc ||sed -i 's/TMOUT.*/TMOUT=600/'  /etc/bashrc

yum update -y sudo 


