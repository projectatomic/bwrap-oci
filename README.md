bwrap-oci
==========

Run an OCI container using Bubblewrap (https://github.com/projectatomic/bubblewrap/).

By default `bwrap-oci` reads the file `config.json` in the
current directory, generates the command line arguments for bubblewrap
and execute it.

You can specify a different configuration file with `--configuration`.

If you are interested to see the generated command line, you can use the `--dry-run`
option to `bwrap-oci`.  This will also stops the creation of the container.
