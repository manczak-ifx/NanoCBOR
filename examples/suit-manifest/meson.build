suit_manifest_sources = [
  'main.c',
  'auth.c',
  'suit_print.c',
  'suit_digest.c',
  'suit_parameters.c',
  'suit_command_sequence.c',
  'suit_common.c',
  'suit_manifest_decoder.c',
]

suit_manifest = executable('suit-manifest', suit_manifest_sources,
                           include_directories : inc,
                           dependencies : dependency('openssl'),
                           link_with : nanocbor_lib)
