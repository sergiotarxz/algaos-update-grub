use v5.38.0;
use Module::Build;

my $build = Module::Build->new(
    module_name => 'AlgaOS::UpdateGrub',
    license     => 'perl',
    requires    => {
        'perl'               => '5.40.0',
        'Crypt::URandom'     => 0,
        'Moo'                => 0,
        'PBKDF2::Tiny'       => 0,
    },
    script_files => [
        'scripts/update-grub',
    ],
);

$build->create_build_script;
