#!/usr/bin/env bash

set -oue pipefail

# SELinux Booleans To Turn Off
sebools=(
    abrt_handle_event
    abrt_upload_watch_anon_write
    auditadm_exec_content
    boinc_execmem
    container_use_dri_devices
    container_user_exec_content
    cron_userdomain_transition
    dbadm_exec_content
    domain_kernel_load_modules
    entropyd_use_audio
    gluster_export_all_rw
    gssd_read_tmp
    guest_exec_content
    httpd_builtin_scripting
    httpd_enable_cgi
    kerberos_enabled
    logadm_exec_content
    logging_syslogd_use_tty
    login_console_enabled
    mcelog_exec_scripts
    mount_anyfile
    mozilla_plugin_can_network_connect
    named_write_master_zones
    nfs_export_all_ro
    nfs_export_all_rw
    nscd_use_shm
    openfortivpn_can_network_connect
    openvpn_can_network_connect
    openvpn_enable_homedirs
    postfix_local_write_mail_spool
    postgresql_selinux_unconfined_dbadm
    postgresql_selinux_users_ddl
    privoxy_connect_any
    secadm_exec_content
    selinuxuser_direct_dri_enabled
    selinuxuser_execheap
    selinuxuser_execmod
    selinuxuser_execstack
    selinuxuser_ping
    selinuxuser_rw_noexattrfile
    spamd_enable_home_dirs
    squid_connect_any
    staff_exec_content
    sysadm_exec_content
    telepathy_tcp_connect_generic_network_ports
    unconfined_chrome_sandbox_transition
    unconfined_mozilla_plugin_transition
    use_virtualbox
    user_exec_content
    virt_sandbox_use_all_caps
    virt_sandbox_use_audit
    virt_use_nfs
    virt_use_usb
    virtqemud_use_execmem
    xend_run_blktap
    xend_run_qemu
    xguest_connect_network
    xguest_exec_content
    xguest_mount_media
    xguest_use_bluetooth
)

for sebool in "${sebools[@]}"; do
        setsebool -P "$sebool" off > /dev/null
done


# SELinux Booleans To Turn On
sebools=(
    deny_bluetooth
    deny_ptrace
    secure_mode
    secure_mode_policyload
)

for sebool in "${sebools[@]}"; do
        setsebool -P "$sebool" on > /dev/null
done