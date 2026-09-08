package AlgaOS::UpdateGrub;

use v5.40.0;

use strict;
use warnings;

use Moo;
use Crypt::URandom qw/urandom/;
use PBKDF2::Tiny;

# Boolean
has search_recovery => ( is => 'ro' );

# Boolean
has search_root => ( is => 'ro' );

# Boolean
has search_live_cd_rootfs => ( is => 'ro' );

# Boolean
has wants_pass_in_sensitive_options => ( is => 'lazy' );

# New pass if wanted will fail if not cached
has change_to_pass => ( is => 'ro' );

# List of users
has user_list => ( is => 'lazy' );

# Target storage device (/dev/sda for example)
has target_device => ( is => 'lazy' );

# What path to use as root
has root_dir => ( is => 'lazy' );

sub _build_target_device {
    my $current_root_part = `findmnt -n -o SOURCE /`;
    die 'Programming error in cd handling'
      if $current_root_part =~ /(?:loop|rootfs)/;
    return '/dev/' . `lsblk -no PKNAME $current_root_part`;
}

sub _build_root_dir {
    return '/';
}

has _devices => ( is => 'lazy' );

sub _build__devices($self) {
    my $target_device = $self->target_device;
    my $devices       = `lsblk -o PARTLABEL,PARTUUID $target_device`;

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
    my $grub_dir = $self->root_dir . '/boot/grub';
    system qw{mkdir -pv}, $grub_dir;
    open my $fh, '>', "$grub_dir/grub.cfg";
    say $fh <<"EOF";
set timeout=5
set default=0
EOF

    my $really_wants_pass = 0;
    if ( $self->wants_pass_in_sensitive_options
        && !$self->search_live_cd_rootfs )
    {
        $really_wants_pass = 1;
        my $hash_complete = $self->_create_or_find_grub_hash;
        say $fh <<"EOF";
set superusers="@{[join ',', @{$self->user_list}]}"

@{[
	join "\n\n", map { "password_pbkdf2 $_ grub.pbkdf2.sha512.$hash_complete" } @{$self->user_list}
]}
EOF
    }
    my %devices;
    my $sort_kernel = sub( $a, $b ) {
        my ($kernel_version_a) = $a =~ m{/kernel-(\d+(?:\.\d+)*)};
        my ($kernel_version_b) = $b =~ m{/kernel-(\d+(?:\.\d+)*)};

        my @version_a = split /\./, $kernel_version_a;
        my @version_b = split /\./, $kernel_version_b;

        my $component_count =
            @version_a > @version_b
          ? @version_a
          : @version_b;

        for my $component_index ( 0 .. $component_count - 1 ) {
            my $comparison =
              ( $version_a[$component_index] // 0 )
              <=> ( $version_b[$component_index] // 0 );

            return -$comparison if $comparison;
        }

        return 0;

    };
    if ( $self->search_root ) {
        %devices = %{ $self->_devices };
        die "Live booting and root requested at once"
          if $self->search_live_cd_rootfs;
        die "No AlgaOSRoot in that device" if !$devices{AlgaOSRoot};
        my @kvers = sort { $sort_kernel->( $a, $b ) }
          glob( $self->root_dir . "/boot/kernel-*" );
        my ($kver) = @kvers;
	$kver =~ s{.*/kernel-}{};
        my $security_string = $really_wants_pass ? '--unrestricted' : '';
        say $fh <<"EOF";
menuentry "AlgaOS" $security_string {
    linux /boot/kernel-$kver root=PARTUUID=$devices{AlgaOSRoot} splash quiet
    initrd /boot/initramfs-$kver.img
}

submenu "En caso de error tras actualizar, prueba estas opciones" {
EOF
        for my $kver (@kvers) {
            die "No kernel found in /boot\n" unless $kver;

            $kver =~ s{.*/kernel-}{};
            my $security_string = $really_wants_pass ? '--unrestricted' : '';
            say $fh <<"EOF";
menuentry "AlgaOS ($kver)" $security_string {
    linux /boot/kernel-$kver root=PARTUUID=$devices{AlgaOSRoot} splash quiet
    initrd /boot/initramfs-$kver.img
}

menuentry "[Arranque de terminal, encuentra problemas] AlgaOS ($kver)" $security_string {
    linux /boot/kernel-$kver root=PARTUUID=$devices{AlgaOSRoot}
    initrd /boot/initramfs-$kver.img
}
EOF
        }
        say $fh "}";
    }
    if ( $self->search_recovery ) {
        %devices = %{ $self->_devices };
        die "Live booting and recovery requested at once"
          if $self->search_live_cd_rootfs;
        die "No AlgaOSRecovery in that device" if !$devices{AlgaOSRecovery};
        my $recovery_title =
          $self->search_root ? 'AlgaOS Recovery' : 'Install AlgaOS now';
        if ( $self->root_dir eq '/' && system qw{mount /recovery} ) {
            die 'Unable to mount /recovery';
        }
        my @rootfs = glob $self->root_dir . '/recovery/*rootfs*.squashfs';
        for my $rootfs (@rootfs) {
            my $tmp_dir = '/tmp/rootfs-uncompression';
            system qw{rm -rf},    $tmp_dir;
            system qw{mkdir -pv}, $tmp_dir;
            system( 'unsquashfs', '-d', $tmp_dir, $rootfs, 'boot/kernel-*',
                'boot/initramfs-*', ) == 0
              or die "unsquashfs failed for $rootfs: $?";
            my (@kernels)  = glob "$tmp_dir/boot/kernel-*";
            my ($kernel)   = sort { $sort_kernel->( $a, $b ) } @kernels;
            my $kver       = $kernel =~ s{^.*kernel-}{}r;
            my $initramfs  = "$tmp_dir/boot/initramfs-$kver.img";
            my $rootfs_ver = $rootfs =~ s/\.squashfs$//r;
            $rootfs_ver = $rootfs_ver =~ s/^.*\///r;

            system qw{mkdir -pv}, $self->root_dir . '/boot/recovery/';
            system "rm -rf " . $self->root_dir . '/boot/recovery/*';
            if ( system qw{cp},
                $kernel, $self->root_dir . "/boot/recovery/kernel-$rootfs_ver" )
            {
                die 'Failed kernel copy';
            }
            if ( system qw{cp},
                $initramfs,
                $self->root_dir . "/boot/recovery/initramfs-$rootfs_ver.img" )
            {
                die 'Failed initramfs copy';
            }

            $rootfs_ver = $rootfs_ver =~ s{^.*\/}{}r;
            my $security_string =
              $really_wants_pass
              ? '--users ' . ( join ',', @{ $self->user_list } )
              : '';
            say $fh <<"EOF";
menuentry "Recupera o Reinstala AlgaOS" $security_string {
    linux /boot/recovery/kernel-$rootfs_ver root=live:PARTUUID=$devices{AlgaOSRecovery} rd.live.dir=/ rd.live.squashimg=$rootfs_ver.squashfs rd.live.overlay.overlayfs=1 rd.live.debug=1 rd.systemd.show_status=1 rd.systemd.log_level=debug splash quiet
    initrd /boot/recovery/initramfs-$rootfs_ver.img
}
EOF
        }

    }

    if ( $self->search_live_cd_rootfs ) {
        my $boot_dir = $self->root_dir . '/boot';
        my ($kernel) = glob "$boot_dir/kernel-*";
        my $kver     = $kernel =~ s/^.*kernel-//;
        say $fh <<"EOF";
menuentry "AlgaOS" {
    linux /boot/kernel-$kver root=live:LABEL=ALGAOS rd.live.dir=/ rd.live.squashimg=rootfs.squashfs rd.live.overlay.overlayfs=1 rd.live.debug=1 rd.systemd.show_status=1 rd.systemd.log_level=debug quiet splash
    initrd /boot/initramfs-$kver.img
}
EOF
    }
}

sub _create_or_find_grub_hash($self) {
    if ( !$self->change_to_pass ) {
        open my $fh, '<', $self->root_dir . '/grub_hash'
          or die 'No grub hash and no pass sent';
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

    my $hash_complete = "$iterations.$salt_hex.$hash";

    open my $fh, '>', $self->root_dir . '/grub_hash';
    print $fh $hash_complete;
    close $fh;
    return $hash_complete;
}
1;
