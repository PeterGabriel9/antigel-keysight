project('dpdk-app', 'c',
  version: '0.1',
  meson_version: '>= 0.53.0',
  default_options: ['buildtype=debugoptimized', 'warning_level=2']
)

dpdk = dependency('libdpdk', required: true)
mhd  = dependency('libmicrohttpd', required: true)

sources = files(
    'main.c',
    'http.c',
)

add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')

executable('netem',
    sources,
    dependencies: [dpdk, mhd],
    install: true
)
