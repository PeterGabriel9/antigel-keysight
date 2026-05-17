project('dpdk-app', 'c',
  version: '0.1',
  meson_version: '>= 0.53.0',
  default_options: ['buildtype=debugoptimized', 'warning_level=2']
)

# 1. Look for the DPDK dependency via pkg-config
# This replaces the old 'include $(RTE_SDK)/mk/rte.vars.mk' logic
dpdk = dependency('libdpdk', required: true)

# 2. Define your source files (similar to l2fwd)
sources = files(
    'main.c',
    # Add other .c files here if you have them
)

# 3. Allow for 'allow_experimental_apis' if you use them
# Many DPDK sample apps require this flag
add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')

# 4. Build the executable
executable('netem',
    sources,
    dependencies: dpdk,
    install: true
)
