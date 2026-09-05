package AlgaOS::UpdateGrub;

use v5.40.0;

use strict;
use warnings;

use Moo;
use Crypt::URandom qw/urandom/;
use PBKDF2::Tiny;

# Boolean
has search_recovery => (is => 'ro');
# Boolean
has search_root => (is => 'ro');
# Boolean
has search_live_cd_rootfs => (is => 'ro');
# Boolean
has wants_pass_in_sensitive_options => (is => 'lazy');
# New pass if wanted will fail if not cached
has change_to_pass => (is => 'ro');
# List of users
has user_list => (is => 'lazy');
# Target storage device (/dev/sda for example)
has target_device => (is => 'lazy');

# What path to use as root
has root_dir => (is => 'lazy');

sub _build_target_device {
    my $current_root_part = `findmnt -n -o SOURCE /`;
    return '/dev/'.`lsblk -no PKNAME $current_root_part`;
}

sub _build_root_dir {
    return '/';
}

has _devices => (is => 'lazy');

sub _build__devices($self) {
    my $target_device = $self->target_device;
    my $devices = `lsblk -o PARTLABEL,PARTUUID $target_device`;

    my @devices = split /\n/, $devices;
    shift @devices;

    @devices = grep { !/^\s*$/ } @devices;

    return { ( map { ( split /\s+/, $_ ) } @devices ) };
}


sub _build_wants_pass_in_sensitive_options {
    return 1;
}

sub _build_user_list {
    return [qw/admin/];
}

sub run($self) {
    my $grub_dir = $self->root_dir.'/boot/grub';
    system qw{mkdir -pv}, $grub_dir;
    open $fh, '>', "$grub_dir/grub.cfg";
    say $fh <<"EOF";
set timeout=5
set default=0
EOF

    my $really_wants_pass = 0;
    if ( $self->wants_pass_in_sensitive_options || !$self->search_live_cd_rootfs ) {
        my $really_wants_pass = 1;
        my $hash_complete = $self->_create_or_find_grub_hash;
        say $fh <<"EOF";
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.$hash_complete
EOF
    }
	my %devices = %{$self->_devices};
    if ($self->search_root) {
        die "Live booting and root requested at once" if $self->search_live_cd_rootfs;
        die "No AlgaOSRoot in that device" if !$devices{AlgaOSRoot};
        for my $kver ( glob($self->root_dir."/boot/kernel-*") ) {
            die "No kernel found in /boot\n" unless $kver;

            $kver =~ s{.*/kernel-}{};
            my $security_string = $really_wants_pass ? '--unrestricted' : '';
            say $fh <<"EOF";
menuentry "AlgaOS" $security_string {
    linux /boot/kernel-$kver root=PARTUUID=$devices{AlgaOSRoot} splash quiet
    initrd /boot/initramfs-$kver.img
};
EOF
        }
    }
    if ($self->search_recovery) {
        die "Live booting and recovery requested at once" if $self->search_live_cd_rootfs;
        die "No AlgaOSRecovery in that device" if !$devices{AlgaOSRecovery};
        my $recovery_title = $self->search_root ? 'AlgaOS Recovery' : 'Install AlgaOS now';
        if (system qw{mount /recovery}) {
            die 'Unable to mount /recovery';
        }
        my @rootfs = glob '/recovery/*rootfs*.squashfs';
        for my $rootfs (@rootfs) {
			my $tmp_dir = '/tmp/rootfs-uncompression';
			system qw{rm -rf}, $tmp_dir;
			system qw{mkdir -pv}, $tmp_dir;
			system(
				'unsquashfs',
				'-d', $dir,
				$rootfs,
				'boot/kernel-*',
				'boot/initramfs-*',
			) == 0 or die "unsquashfs failed for $rootfs: $?";
			my ($kernel) = glob "$tmp_dir/kernel-*";
            my $kver = $kernel =~ s{.*/kernel-}{}r;
			my $intramfs = "$tmp_dir/initramfs-$kver.img";
			if (system qw{cp}, $kernel, "/boot/recovery/kernel-$rootfs_ver") {
				die 'Failed kernel copy';
			}
			if (system qw{cp}, $initramfs, "/boot/recovery/initramfs-$rootfs_ver.img") {
				die 'Failed initramfs copy';
			}

			my $rootfs_ver = $rootfs =~ s/\.squashfs$//r;
			$rootfs_ver = $rootfs_ver =~ s{^.*\/}{}r;
            my $security_string = $really_wants_pass ? '--users '.(join ',', @{$self->user_list}) : '';
            say $fh <<"EOF";
menuentry "AlgaOS Recovery" $security_string {
    linux /boot/recovery/kernel-$rootfs_ver root=live:PARTUUID=$devices{AlgaOSRecovery} rd.live.dir=/ rd.live.squashimg=$rootfs_ver.squashfs rd.live.overlay.overlayfs=1 rd.live.debug=1 rd.systemd.show_status=1 rd.systemd.log_level=debug splash quiet
    initrd /boot/recovery/initramfs-$rootfs_ver.img
};
EOF
        }

        if ($self->search_live_cd_rootfs) {
        my $boot_dir = $self->root_dir . '/boot';
        my ($kernel) = glob "$boot_dir/kernel-*";
        my $kver = s/^.*kernel-//;
say $fh <<"EOF";
menuentry "AlgaOS" {
    linux /boot/kernel-$kver root=live:LABEL=ALGAOS rd.live.dir=/ rd.live.squashimg=rootfs.squashfs rd.live.overlay.overlayfs=1 rd.live.debug=1 rd.systemd.show_status=1 rd.systemd.log_level=debug quiet splash
    initrd /boot/initramfs-$kver.img
};
EOF
        }

    }
}

sub _create_or_find_grub_hash {
    if ( !$self->change_to_pass ) {
        open $fh, '<', '/grub_hash';
        local $/ = undef;
        my $hash_complete = <$fh>;
        close $fh;
        return $hash_complete if $hash_complete;
    }
    my $salt       = urandom(64);
    my $salt_hex   = unpack( 'H*', $salt );
    my $iterations = 1000;
    my $password   = $self->change_to_pass;

    die 'No pass sent, no cached one, send pass' if !$password;

    my $hash =
      PBKDF2::Tiny::derive_hex( 'SHA-512', $password, $salt, $iterations, 64 );

    $hash_complete = "$iterations.$salt_hex.$hash";

    open my $fh, '>', '/grub_hash';
    print $fh $hash_complete;
    close $fh;
    return $hash_complete;
}
1;
